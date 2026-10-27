// Discover and decompile native ELF functions without IL2CPP metadata.
// Optional 4th argument: a file of function entry offsets (hex, from the image base), read
// from .eh_frame_hdr, so functions are created without Ghidra's global Auto Analyze.
//@category DucAPK
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

public class DucAPKNative extends GhidraScript {
    private String encode(String text) {
        return Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8));
    }

    private static int threadCount() {
        String configured = System.getenv("DUCAPK_GHIDRA_THREADS");
        if (configured != null) {
            try {
                return Math.max(1, Integer.parseInt(configured.trim()));
            } catch (NumberFormatException ignored) { }
        }
        return Math.max(1, Runtime.getRuntime().availableProcessors() - 2);
    }

    private void createFunctions(File startsFile) throws Exception {
        // "entry size" per line (hex); size comes from the function's FDE, 0 when unknown.
        List<long[]> starts = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(startsFile, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.trim().split(" ");
                if (parts[0].isEmpty()) continue;
                starts.add(new long[] { Long.parseUnsignedLong(parts[0], 16),
                    parts.length > 1 ? Long.parseUnsignedLong(parts[1], 16) : 0 });
            }
        }
        Address base = currentProgram.getImageBase();
        Set<Address> exactBodies = new HashSet<>();
        int created = 0, index = 0;
        for (long[] start : starts) {
            monitor.checkCancelled();
            index++;
            try {
                Address address = base.add(start[0]);
                if (!currentProgram.getMemory().contains(address) || getFunctionAt(address) != null) continue;
                if (start[1] > 0) {
                    // The exact extent keeps a body from running into the next function after a
                    // call that never returns, which Auto Analyze would otherwise have to discover.
                    AddressSet body = new AddressSet(address, address.add(start[1] - 1));
                    new DisassembleCommand(address, body, true).applyTo(currentProgram, monitor);
                    if (new CreateFunctionCmd(null, address, body, SourceType.DEFAULT).applyTo(currentProgram, monitor)) {
                        created++;
                        exactBodies.add(address);
                    }
                } else {
                    if (getInstructionAt(address) == null) disassemble(address);
                    if (createFunction(address, null) != null) created++;
                }
            } catch (Exception ignored) { }
            if (index % 5000 == 0) println("DUCAPK_PREPARE " + index + "/" + starts.size() + " created=" + created);
        }
        println("Native functions created from .eh_frame: " + created + "/" + starts.size());
        createPltThunks();
        markNoReturn(exactBodies);
        defineStrings();
    }

    /** PLT stubs are not in .eh_frame; as thunks they let calls show the imported name. */
    private void createPltThunks() throws Exception {
        int thunks = 0;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.getName().startsWith(".plt") || !block.isExecute() || !block.isInitialized()) continue;
            Address address = block.getStart();
            while (address != null && address.compareTo(block.getEnd()) <= 0) {
                monitor.checkCancelled();
                if (getInstructionAt(address) == null) disassemble(address);
                Instruction instruction = getInstructionAt(address);
                address = instruction == null ? address.add(4) : instruction.getMaxAddress().next();
            }
            // A stub ends with an indirect jump; padding NOPs (the ARM64 PLT header has three)
            // belong to no stub.
            List<Address> stubs = new ArrayList<>();
            Address stub = null;
            for (Instruction instruction : currentProgram.getListing().getInstructions(
                    new AddressSet(block.getStart(), block.getEnd()), true)) {
                if (stub == null) {
                    if (instruction.getMnemonicString().equalsIgnoreCase("nop")) continue;
                    stub = instruction.getAddress();
                }
                // "br x17" is a COMPUTED_CALL_TERMINATOR, "jmp [got]" a COMPUTED_JUMP.
                if (instruction.getFlowType().isComputed() &&
                        (instruction.getFlowType().isJump() || instruction.getFlowType().isTerminal())) {
                    stubs.add(stub);
                    stub = null;
                }
            }
            // Without analysis Ghidra cannot follow a stub to its GOT slot, but lazy-binding PLTs
            // keep stubs in the same order as the JUMP_SLOT relocations, which carry the name.
            // JUMP_SLOTs live in .got.plt when it exists; .got also holds named GLOB_DAT slots.
            boolean hasGotPlt = currentProgram.getMemory().getBlock(".got.plt") != null;
            List<Relocation> slots = new ArrayList<>();
            for (MemoryBlock got : currentProgram.getMemory().getBlocks()) {
                if (!got.getName().equals(hasGotPlt ? ".got.plt" : ".got")) continue;
                Iterator<Relocation> relocations = currentProgram.getRelocationTable()
                    .getRelocations(new AddressSet(got.getStart(), got.getEnd()));
                while (relocations.hasNext()) {
                    Relocation relocation = relocations.next();
                    if (relocation.getSymbolName() != null && !relocation.getSymbolName().isEmpty()) slots.add(relocation);
                }
            }
            slots.sort(Comparator.comparing(Relocation::getAddress));
            if (stubs.size() == slots.size() + 1) stubs.remove(0);  // the resolver header
            boolean named = stubs.size() == slots.size();
            for (int i = 0; i < stubs.size(); i++) {
                Address entry = stubs.get(i);
                Function function = getFunctionAt(entry);
                if (function == null) function = createFunction(entry, null);
                if (function == null || !named) continue;
                String name = slots.get(i).getSymbolName();
                Function target = null;
                Data pointer = getDataAt(slots.get(i).getAddress());
                if (pointer != null && pointer.getValue() instanceof Address) target = getFunctionAt((Address) pointer.getValue());
                try {
                    if (target != null && target != function) function.setThunkedFunction(target);
                    else function.setName(name, SourceType.IMPORTED);
                    thunks++;
                } catch (Exception error) {
                    try { function.setName(name, SourceType.IMPORTED); thunks++; } catch (Exception ignored) { }
                }
            }
        }
        println("Native PLT thunks: " + thunks);
    }

    /**
     * The decompiler follows flow on its own; past a call to abort/__cxa_throw it would decode
     * the following functions until it times out. Auto Analyze marks such callees no-return;
     * here: imports named in Ghidra's ElfFunctionsThatDoNotReturn list, plus every function
     * whose FDE-sized body ends with a call (nothing after the call belongs to it).
     */
    private void markNoReturn(Set<Address> exactBodies) throws Exception {
        Set<String> names = new HashSet<>(Arrays.asList("cxa_rethrow", "cxa_pure_virtual",
            "cxa_deleted_virtual", "assert2", "android_log_assert", "pthread_exit", "terminate"));
        try {
            File list = ghidra.framework.Application.getModuleDataFile("Base", "ElfFunctionsThatDoNotReturn").getFile(false);
            for (String line : java.nio.file.Files.readAllLines(list.toPath())) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) names.add(line);
            }
        } catch (Exception ignored) { }
        int marked = 0;
        List<Function> all = new ArrayList<>();
        currentProgram.getFunctionManager().getFunctions(true).forEach(all::add);
        currentProgram.getFunctionManager().getExternalFunctions().forEach(all::add);
        for (Function function : all) {
            monitor.checkCancelled();
            if (function.hasNoReturn()) continue;
            String name = function.getName().replaceFirst("^_+", "");
            boolean noReturn = names.contains(name) || name.contains("__throw_") || name.matches("ZSt\\d+terminatev");
            if (!noReturn && !function.isExternal() && !function.isThunk() && exactBodies.contains(function.getEntryPoint()))
                noReturn = neverReturns(function);
            if (noReturn) {
                try { function.setNoReturn(true); marked++; } catch (Exception ignored) { }
            }
        }
        println("Native no-return functions: " + marked);
    }

    /**
     * True when no path leaves the FDE-sized body: no return, no tail jump out of it, no
     * indirect jump, no fall-through past its end, and the code ends in a call. A trailing
     * "bl __stack_chk_fail" after a normal "ret" therefore does not count.
     */
    private boolean neverReturns(Function function) {
        AddressSetView body = function.getBody();
        Instruction last = null;
        for (Instruction instruction : currentProgram.getListing().getInstructions(body, true)) {
            FlowType flow = instruction.getFlowType();
            if (flow.isCall()) {
                if (flow.isTerminal()) return false;  // indirect tail call ("br x17")
            } else if (flow.isTerminal() || flow.isComputed()) {
                return false;  // return, or a jump table / indirect jump
            } else if (flow.isJump()) {
                for (Address target : instruction.getFlows())
                    if (!body.contains(target)) return false;  // tail call
            }
            last = instruction;
        }
        return last != null && last.getFlowType().isCall() && !last.getFlowType().isTerminal();
    }

    /**
     * NUL-terminated text in read-only data becomes string data, so the decompiler prints
     * literals. Done by hand: Ghidra's string analyzer would also run every analyzer queued
     * by the function creation above, which amounts to a full Auto Analyze.
     */
    private void defineStrings() throws Exception {
        int defined = 0;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.isInitialized() || block.isExecute() || block.isWrite() || !block.getName().contains("rodata")
                    || block.getSize() > Integer.MAX_VALUE) continue;
            byte[] bytes = new byte[(int) block.getSize()];
            block.getBytes(block.getStart(), bytes);
            int i = 0;
            while (i < bytes.length) {
                monitor.checkCancelled();
                int j = i;
                while (j < bytes.length && printable(bytes[j])) j++;
                if (j < bytes.length && bytes[j] == 0 && j - i >= 4) {
                    Address address = block.getStart().add(i);
                    try {
                        DataUtilities.createData(currentProgram, address, TerminatedStringDataType.dataType,
                            j - i + 1, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
                        defined++;
                    } catch (Exception ignored) { }
                }
                i = j + 1;
            }
        }
        println("Native strings defined: " + defined);
    }

    private static boolean printable(byte value) {
        int b = value & 0xFF;
        return (b >= 0x20 && b < 0x7F) || b == 0x09 || b == 0x0A || b == 0x0D || b >= 0x80;
    }

    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        File directory = new File(args[0]);
        int limit = Integer.parseInt(args[1]);
        boolean bodies = Boolean.parseBoolean(args[2]);
        if (args.length > 3 && !args[3].isEmpty()) createFunctions(new File(args[3]));
        List<Function> functions = new ArrayList<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Function fn = iterator.next();
            if (!fn.isExternal() && !fn.isThunk()) functions.add(fn);
        }
        // Preserve a completed manifest across resume; indices are in address order.
        File manifest = new File(directory, "methods.tsv");
        File temporary = new File(directory, "methods.pending.tsv");
        try (PrintWriter out = new PrintWriter(temporary, StandardCharsets.UTF_8)) {
            int index = 0;
            for (Function fn : functions) {
                out.println((++index) + "\t" + fn.getEntryPoint().toString() + "\t" +
                    encode(fn.getName()) + "\t" + encode(fn.getParentNamespace().getName(true)) +
                    "\t" + encode(fn.getSignature().getPrototypeString()));
            }
        }
        java.nio.file.Files.move(temporary.toPath(), manifest.toPath(),
            java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        println("Native functions discovered: " + functions.size());
        if (!bodies) {
            new File(directory, "script_complete").createNewFile();
            return;
        }
        // Key cached results by address so a fresh analysis cannot reuse the wrong function.
        File resultFile = new File(directory, "results.tsv");
        Set<String> done = new HashSet<>();
        if (resultFile.isFile()) {
            try (BufferedReader old = new BufferedReader(new FileReader(resultFile, StandardCharsets.UTF_8))) {
                String line;
                while ((line = old.readLine()) != null) {
                    String[] fields = line.split("\t", -1);
                    if (fields.length == 3 && fields[1].equals("ok") && !fields[2].isEmpty()) {
                        try {
                            if (!new String(Base64.getDecoder().decode(fields[2]), StandardCharsets.UTF_8).trim().isEmpty())
                                done.add(fields[0]);
                        } catch (IllegalArgumentException ignored) { }
                    }
                }
            }
        }
        // Named functions (exports, JNI entry points, symbols) say the most; decompile them first.
        List<Function> work = new ArrayList<>();
        for (Function fn : functions) {
            if (!done.contains(fn.getEntryPoint().toString())) work.add(fn);
        }
        work.sort(Comparator.comparingInt(fn -> fn.getSymbol().getSource() == SourceType.DEFAULT ? 1 : 0));
        if (limit > 0 && work.size() > limit) work = work.subList(0, limit);

        int total = functions.size(), threads = threadCount();
        println("DUCAPK_THREADS " + threads);
        AtomicInteger finished = new AtomicInteger(done.size());
        AtomicInteger successful = new AtomicInteger(done.size());
        List<DecompInterface> decompilers = Collections.synchronizedList(new ArrayList<>());
        ThreadLocal<DecompInterface> local = ThreadLocal.withInitial(() -> {
            DecompInterface decompiler = new DecompInterface();
            decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(false);
            if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("Cannot open native program");
            decompilers.add(decompiler);
            return decompiler;
        });
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try (PrintWriter out = new PrintWriter(new FileOutputStream(resultFile, true), true, StandardCharsets.UTF_8)) {
            List<Future<?>> futures = new ArrayList<>();
            for (Function fn : work) {
                futures.add(pool.submit(() -> {
                    String address = fn.getEntryPoint().toString(), status = "error", body;
                    try {
                        DecompileResults result = local.get().decompileFunction(fn, 30, TaskMonitor.DUMMY);
                        if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                            body = result.getDecompiledFunction().getC();
                            status = body.trim().isEmpty() ? "empty" : "ok";
                        } else {
                            status = result.isTimedOut() ? "timeout" : "error";
                            body = result.getErrorMessage();
                        }
                    } catch (Exception error) { body = error.toString(); }
                    int ok = status.equals("ok") ? successful.incrementAndGet() : successful.get();
                    int current = finished.incrementAndGet();
                    synchronized (out) {
                        out.println(address + "\t" + status + "\t" + encode(body == null ? "" : body));
                        if (out.checkError()) throw new IOException("Cannot save native results");
                    }
                    println("DUCAPK_CURRENT " + current + "/" + total + " " + fn.getName());
                    println("DUCAPK_PROGRESS " + current + "/" + total + " ok=" + ok);
                    return null;
                }));
            }
            for (Future<?> future : futures) {
                while (!future.isDone()) {
                    if (monitor.isCancelled()) {
                        pool.shutdownNow();
                        monitor.checkCancelled();
                    }
                    Thread.sleep(100);
                }
                future.get();
            }
        } finally {
            pool.shutdownNow();
            for (DecompInterface decompiler : decompilers) decompiler.dispose();
        }
        new File(directory, "script_complete").createNewFile();
    }
}
