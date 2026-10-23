// Decompile metadata-mapped IL2CPP methods without global Auto Analyze.
//@category DucAPK

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

public class DucAPKDecompile extends GhidraScript {
    private static final int DEFAULT_TIMEOUT_SECONDS = 30;
    // Sorted RVAs of every metadata method; marks where each function must end.
    private long[] methodStarts;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if ((args.length != 4 && args.length != 7 && args.length != 8) || currentProgram == null) {
            throw new IllegalArgumentException(
                "Expected: methods.tsv results.tsv startIndex endIndex " +
                "[timeoutSeconds simplificationStyle overallTotal [overallOffset]]");
        }
        File manifest = new File(args[0]);
        File output = new File(args[1]);
        int start = Integer.parseInt(args[2]);
        int end = Integer.parseInt(args[3]);
        int timeoutSeconds = args.length >= 7 ? Integer.parseInt(args[4]) : DEFAULT_TIMEOUT_SECONDS;
        String simplificationStyle = args.length >= 7 ? args[5] : "decompile";
        int overallTotal = args.length >= 7 ? Integer.parseInt(args[6]) : end;
        int overallOffset = args.length == 8 ? Integer.parseInt(args[7]) : start - 1;
        methodStarts = loadMethodStarts(System.getenv("DUCAPK_METHOD_INDEX"));
        Set<Integer> done = new HashSet<Integer>();
        if (output.isFile()) {
            try (BufferedReader old = new BufferedReader(new InputStreamReader(
                    new FileInputStream(output), StandardCharsets.UTF_8))) {
                String line;
                while ((line = old.readLine()) != null) {
                    int tab = line.indexOf('\t');
                    if (tab > 0) {
                        try {
                            done.add(Integer.parseInt(line.substring(0, tab)));
                        }
                        catch (NumberFormatException ignored) { }
                    }
                }
            }
        }

        // Function creation mutates the program, so it stays on this thread; the
        // read-only decompile step then runs on one DecompInterface per worker.
        int threads = threadCount();
        println("DUCAPK_THREADS " + threads);
        monitor.initialize(end - start + 1);
        List<Task> tasks = new ArrayList<Task>();
        AtomicInteger finished = new AtomicInteger();
        AtomicInteger attempted = new AtomicInteger();
        AtomicInteger successful = new AtomicInteger();
        List<DecompInterface> decompilers = new ArrayList<DecompInterface>();
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    new FileInputStream(manifest), StandardCharsets.UTF_8));
             BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream(output, true), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                monitor.checkCancelled();
                String[] parts = line.split("\t", -1);
                if (parts.length != 5 && parts.length != 6) {
                    continue;
                }
                int index = Integer.parseInt(parts[0]);
                boolean selectedManifest = parts.length == 6;
                int resultIndex = selectedManifest ? Integer.parseInt(parts[1]) : index;
                int dataStart = selectedManifest ? 2 : 1;
                if (index < start) {
                    continue;
                }
                if (index > end) {
                    break;
                }
                if (done.contains(resultIndex)) {
                    finished.incrementAndGet();
                    continue;
                }
                long offset = Long.parseLong(parts[dataStart]);
                String className = fromBase64(parts[dataStart + 1]);
                String methodName = fromBase64(parts[dataStart + 2]);
                Task task = new Task(resultIndex, className + "::" + methodName);
                try {
                    Address address = currentProgram.getImageBase().add(offset);
                    if (!currentProgram.getMemory().contains(address)) {
                        task.status = "missing";
                        task.body = "Address is outside the loaded binary";
                    }
                    else {
                        if (getInstructionAt(address) == null) {
                            disassemble(address);
                        }
                        Function function = getFunctionAt(address);
                        if (function == null) {
                            function = createFunction(address, null);
                        }
                        else if (function.getBody().getNumAddresses() <= 4) {
                            // DucAPKApplyMetadata creates entry-only functions for names
                            // and signatures; compute the real body before decompiling.
                            CreateFunctionCmd.fixupFunctionBody(currentProgram, function, monitor);
                        }
                        if (function == null) {
                            task.status = "missing";
                            task.body = "Could not create a function at the metadata address";
                        }
                        else {
                            fixTailCalls(function, offset);
                            String safeName = (className + "__" + methodName)
                                .replaceAll("[^A-Za-z0-9_]", "_");
                            if (safeName.length() > 90) {
                                safeName = safeName.substring(0, 90);
                            }
                            safeName = "IL2CPP_" + safeName + "_" + Long.toHexString(offset);
                            try {
                                function.setName(safeName, SourceType.USER_DEFINED);
                            }
                            catch (Exception ignored) { }
                            task.function = function;
                        }
                    }
                }
                catch (Exception error) {
                    task.status = "error";
                    task.body = error.toString();
                }
                tasks.add(task);
            }

            ThreadLocal<DecompInterface> local = ThreadLocal.withInitial(() -> {
                DecompInterface decompiler = new DecompInterface();
                decompiler.toggleCCode(true);
                decompiler.toggleSyntaxTree(false);
                decompiler.setSimplificationStyle(simplificationStyle);
                if (!decompiler.openProgram(currentProgram)) {
                    throw new IllegalStateException("Could not open this program in Ghidra decompiler");
                }
                synchronized (decompilers) {
                    decompilers.add(decompiler);
                }
                return decompiler;
            });
            List<Future<?>> futures = new ArrayList<Future<?>>();
            for (Task task : tasks) {
                futures.add(pool.submit(() -> {
                    if (task.function != null) {
                        report("DUCAPK_CURRENT " + (overallOffset + finished.get() + 1) + "/" +
                            overallTotal + " " + task.label);
                        try {
                            DecompileResults result = local.get().decompileFunction(
                                task.function, timeoutSeconds, TaskMonitor.DUMMY);
                            if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                                task.body = result.getDecompiledFunction().getC();
                                task.status = task.body == null || task.body.trim().isEmpty()
                                    ? "empty" : "ok";
                            }
                            else {
                                task.body = result.getErrorMessage();
                                task.status = "failed";
                            }
                        }
                        catch (Exception error) {
                            task.status = "error";
                            task.body = error.toString();
                        }
                    }
                    if ("ok".equals(task.status)) {
                        successful.incrementAndGet();
                    }
                    attempted.incrementAndGet();
                    int current = finished.incrementAndGet();
                    synchronized (writer) {
                        writer.write(task.resultIndex + "\t" + task.status + "\t" +
                            toBase64(task.body) + "\n");
                        writer.flush();
                    }
                    monitor.setProgress(current);
                    report("DUCAPK_PROGRESS " + (overallOffset + current) + "/" + overallTotal +
                        " ok=" + successful.get());
                    return null;
                }));
            }
            for (Future<?> future : futures) {
                while (!future.isDone()) {
                    if (monitor.isCancelled()) {
                        pool.shutdownNow();
                        monitor.checkCancelled();
                    }
                    Thread.sleep(200);
                }
                future.get();
            }
        }
        finally {
            pool.shutdownNow();
            synchronized (decompilers) {
                for (DecompInterface decompiler : decompilers) {
                    decompiler.dispose();
                }
            }
        }
        println("DUCAPK_BATCH_DONE " + start + "-" + end +
            " attempted=" + attempted.get() + " ok=" + successful.get());
    }

    /**
     * Without Auto Analyze Ghidra treats an IL2CPP tail call ("b OtherMethod") as
     * an in-function jump and the decompiler can stall until it times out. Any
     * unconditional or conditional branch leaving [entry, next metadata method) is
     * marked CALL_RETURN, then the body is recomputed so it stops at the boundary.
     * Likewise a call whose fall-through is the next method (an IL2CPP throw
     * helper such as raising NullReferenceException) never returns, so it is
     * marked CALL_RETURN to stop the body from running into the neighbour.
     */
    private void fixTailCalls(Function function, long offset) throws Exception {
        if (methodStarts == null) {
            return;
        }
        Address start = function.getEntryPoint();
        int next = Arrays.binarySearch(methodStarts, offset + 1);
        next = next < 0 ? -next - 1 : next;
        Address end = next < methodStarts.length
            ? currentProgram.getImageBase().add(methodStarts[next]) : null;
        boolean changed = false;
        for (Instruction instruction : currentProgram.getListing().getInstructions(start, true)) {
            Address at = instruction.getAddress();
            if (end != null && at.compareTo(end) >= 0) {
                break;
            }
            if (!function.getBody().contains(at)) {
                continue;
            }
            FlowType flow = instruction.getFlowType();
            if (instruction.getFlowOverride() != FlowOverride.NONE) {
                continue;
            }
            if (flow.isCall()) {
                Address fallThrough = instruction.getFallThrough();
                if (end != null && fallThrough != null && fallThrough.compareTo(end) >= 0) {
                    instruction.setFlowOverride(FlowOverride.CALL_RETURN);
                    changed = true;
                }
                continue;
            }
            if (!flow.isJump() || flow.isComputed()) {
                continue;
            }
            Address[] targets = instruction.getFlows();
            if (targets.length != 1) {
                continue;
            }
            Address target = targets[0];
            if (target.compareTo(start) >= 0 && (end == null || target.compareTo(end) < 0)) {
                continue;
            }
            instruction.setFlowOverride(FlowOverride.CALL_RETURN);
            changed = true;
        }
        if (changed) {
            CreateFunctionCmd.fixupFunctionBody(currentProgram, function, monitor);
        }
    }

    private static long[] loadMethodStarts(String path) throws Exception {
        if (path == null || !new File(path).isFile()) {
            return null;
        }
        List<Long> starts = new ArrayList<Long>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new FileInputStream(path), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split("	", 3);
                if (parts.length == 3) {
                    try {
                        starts.add(Long.parseLong(parts[1]));
                    }
                    catch (NumberFormatException ignored) { }
                }
            }
        }
        long[] sorted = new long[starts.size()];
        for (int i = 0; i < sorted.length; i++) {
            sorted[i] = starts.get(i);
        }
        Arrays.sort(sorted);
        return sorted;
    }

    private synchronized void report(String message) {
        println(message);
    }

    private static int threadCount() {
        String configured = System.getenv("DUCAPK_GHIDRA_THREADS");
        if (configured != null) {
            try {
                return Math.max(1, Integer.parseInt(configured.trim()));
            }
            catch (NumberFormatException ignored) { }
        }
        return Math.max(1, Math.min(16, Runtime.getRuntime().availableProcessors() - 2));
    }

    private static final class Task {
        final int resultIndex;
        final String label;
        Function function;
        String status = "failed";
        String body = "";

        Task(int resultIndex, String label) {
            this.resultIndex = resultIndex;
            this.label = label;
        }
    }

    private static String fromBase64(String value) {
        return new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8);
    }

    private static String toBase64(String value) {
        if (value == null) {
            value = "";
        }
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
