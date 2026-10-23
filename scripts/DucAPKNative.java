// Discover and decompile native ELF functions without IL2CPP metadata.
//@category DucAPK
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class DucAPKNative extends GhidraScript {
    private String encode(String text) {
        return Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8));
    }
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        File directory = new File(args[0]);
        int limit = Integer.parseInt(args[1]);
        boolean bodies = Boolean.parseBoolean(args[2]);
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
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(false);
            if (!decompiler.openProgram(currentProgram)) throw new IOException("Cannot open native program");
            try (PrintWriter out = new PrintWriter(new FileOutputStream(resultFile, true), true, StandardCharsets.UTF_8)) {
                int total = functions.size(), successful = done.size(), attempted = 0;
                for (int i = 0; i < total; i++) {
                    monitor.checkCancelled();
                    int index = i + 1;
                    Function fn = functions.get(i);
                    String address = fn.getEntryPoint().toString();
                    if (done.contains(address)) continue;
                    if (limit > 0 && attempted >= limit) break;
                    attempted++;
                    println("DUCAPK_CURRENT " + index + "/" + total + " " + fn.getName());
                    String status = "error", body;
                    try {
                        DecompileResults result = decompiler.decompileFunction(fn, 30, monitor);
                        if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                            body = result.getDecompiledFunction().getC();
                            status = body.trim().isEmpty() ? "empty" : "ok";
                        } else {
                            status = result.isTimedOut() ? "timeout" : "error";
                            body = result.getErrorMessage();
                        }
                    } catch (Exception error) { body = error.toString(); }
                    out.println(address + "\t" + status + "\t" + encode(body == null ? "" : body));
                    if (out.checkError()) throw new IOException("Cannot save native results");
                    if (status.equals("ok")) successful++;
                    println("DUCAPK_PROGRESS " + index + "/" + total + " ok=" + successful);
                }
            }
        } finally { decompiler.dispose(); }
        new File(directory, "script_complete").createNewFile();
    }
}
