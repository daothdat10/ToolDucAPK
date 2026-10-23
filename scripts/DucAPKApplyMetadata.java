// Load Il2CppDumper types and names into the program before decompiling.
//@category DucAPK

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;

/**
 * Arguments: metaDir methods.tsv
 *
 * metaDir holds files prepared by ducapk.runner: il2cpp_ghidra.h (Il2CppDumper
 * il2cpp.h made parseable), strings.tsv and metadata.tsv. Every metadata method
 * gets a function named like DucAPKDecompile names it, with its IL2CPP signature,
 * so callers show real names, parameters and struct field names. Bodies are left
 * minimal here; DucAPKDecompile computes the body of each function it decompiles.
 */
public class DucAPKApplyMetadata extends GhidraScript {
    private final Map<String, DataType> types = new HashMap<String, DataType>();
    private DataTypeManager dtm;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 || currentProgram == null) {
            throw new IllegalArgumentException("Expected: metaDir methods.tsv");
        }
        File dir = new File(args[0]);
        dtm = currentProgram.getDataTypeManager();

        long started = System.currentTimeMillis();
        println("DUCAPK_META header");
        CParser parser = new CParser(dtm, true, null);
        try (InputStream in = new FileInputStream(new File(dir, "il2cpp_ghidra.h"))) {
            parser.parse(in);
        }
        Iterator<DataType> all = dtm.getAllDataTypes();
        while (all.hasNext()) {
            DataType type = all.next();
            types.putIfAbsent(type.getName(), type);
        }
        println("DUCAPK_META types=" + types.size() + " seconds=" + seconds(started));

        int methods = applyMethods(new File(args[1]));
        println("DUCAPK_META methods=" + methods + " seconds=" + seconds(started));
        int strings = applyStrings(new File(dir, "strings.tsv"));
        println("DUCAPK_META strings=" + strings + " seconds=" + seconds(started));
        int metadata = applyMetadata(new File(dir, "metadata.tsv"));
        println("DUCAPK_META metadata=" + metadata + " seconds=" + seconds(started));
        println("DUCAPK_META_DONE");
    }

    private int applyMethods(File manifest) throws Exception {
        int count = 0;
        Address base = currentProgram.getImageBase();
        try (BufferedReader reader = reader(manifest)) {
            String line;
            while ((line = reader.readLine()) != null) {
                monitor.checkCancelled();
                String[] parts = line.split("\t", -1);
                if (parts.length != 5) {
                    continue;
                }
                long offset = Long.parseLong(parts[1]);
                Address address = base.add(offset);
                if (!currentProgram.getMemory().contains(address)) {
                    continue;
                }
                String name = functionName(decode(parts[2]), decode(parts[3]), offset);
                try {
                    Function function = getFunctionAt(address);
                    if (function == null) {
                        function = currentProgram.getFunctionManager().createFunction(
                            name, address, new AddressSet(address), SourceType.USER_DEFINED);
                    }
                    else {
                        function.setName(name, SourceType.USER_DEFINED);
                    }
                    applySignature(function, decode(parts[4]));
                    count++;
                }
                catch (Exception ignored) {
                    // Overlapping or invalid entries keep Ghidra's defaults.
                }
            }
        }
        return count;
    }

    /** Same naming scheme as DucAPKDecompile so callers and callees match. */
    static String functionName(String className, String methodName, long offset) {
        String safeName = (className + "__" + methodName).replaceAll("[^A-Za-z0-9_]", "_");
        if (safeName.length() > 90) {
            safeName = safeName.substring(0, 90);
        }
        return "IL2CPP_" + safeName + "_" + Long.toHexString(offset);
    }

    /** Parse "Ret Name (T1* a, T2 b, const MethodInfo* method);" without the C parser. */
    private void applySignature(Function function, String signature) throws Exception {
        int open = signature.indexOf('(');
        int close = signature.lastIndexOf(')');
        if (open < 0 || close < open) {
            return;
        }
        String head = signature.substring(0, open).trim();
        int space = head.lastIndexOf(' ');
        if (space < 0) {
            return;
        }
        DataType returnType = resolve(head.substring(0, space));
        List<Parameter> params = new ArrayList<Parameter>();
        String inner = signature.substring(open + 1, close).trim();
        if (!inner.isEmpty() && !inner.equals("void")) {
            int index = 0;
            for (String raw : inner.split(",")) {
                String param = raw.trim();
                int split = Math.max(param.lastIndexOf(' '), param.lastIndexOf('*'));
                if (split <= 0) {
                    return;
                }
                String paramName = param.substring(split + 1).trim();
                String paramType = param.substring(0, split + 1).trim();
                if (paramName.isEmpty()) {
                    paramName = "p" + index;
                }
                params.add(new ParameterImpl(paramName, resolve(paramType), currentProgram));
                index++;
            }
        }
        function.updateFunction(callingConvention(), new ReturnParameterImpl(returnType, currentProgram), params,
            FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
    }

    private String callingConvention() {
        return currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();
    }

    private DataType resolve(String text) {
        String name = text.replace("const ", "").replace("struct ", "").trim();
        int pointers = 0;
        while (name.endsWith("*")) {
            pointers++;
            name = name.substring(0, name.length() - 1).trim();
        }
        DataType type = name.equals("void") ? VoidDataType.dataType : types.get(name);
        if (type == null) {
            type = pointers > 0 ? VoidDataType.dataType : Undefined8DataType.dataType;
        }
        for (int i = 0; i < pointers; i++) {
            type = new PointerDataType(type, dtm);
        }
        return type;
    }

    private int applyStrings(File file) throws Exception {
        if (!file.isFile()) {
            return 0;
        }
        DataType stringType = types.get("System_String_o");
        DataType pointer = stringType == null ? null : new PointerDataType(stringType, dtm);
        int count = 0;
        int index = 1;
        Address base = currentProgram.getImageBase();
        try (BufferedReader reader = reader(file)) {
            String line;
            while ((line = reader.readLine()) != null) {
                monitor.checkCancelled();
                String[] parts = line.split("\t", -1);
                if (parts.length != 2) {
                    continue;
                }
                Address address = base.add(Long.parseLong(parts[0]));
                String value = decode(parts[1]);
                String label = value.replaceAll("[^A-Za-z0-9]+", "_");
                if (label.length() > 40) {
                    label = label.substring(0, 40);
                }
                try {
                    createLabel(address, "StringLiteral_" + index + (label.isEmpty() ? "" : "_" + label),
                        true, SourceType.USER_DEFINED);
                    setEOLComment(address, value);
                    if (pointer != null) {
                        clearListing(address, address.add(pointer.getLength() - 1));
                        createData(address, pointer);
                    }
                    count++;
                }
                catch (Exception ignored) { }
                index++;
            }
        }
        return count;
    }

    private int applyMetadata(File file) throws Exception {
        if (!file.isFile()) {
            return 0;
        }
        int count = 0;
        Address base = currentProgram.getImageBase();
        try (BufferedReader reader = reader(file)) {
            String line;
            while ((line = reader.readLine()) != null) {
                monitor.checkCancelled();
                String[] parts = line.split("\t", -1);
                if (parts.length != 3) {
                    continue;
                }
                Address address = base.add(Long.parseLong(parts[0]));
                String name = decode(parts[1]).replace(' ', '-');
                String signature = decode(parts[2]);
                try {
                    createLabel(address, name, true, SourceType.USER_DEFINED);
                    if (!signature.isEmpty()) {
                        DataType type = resolve(signature);
                        if (!(type instanceof VoidDataType)) {
                            clearListing(address, address.add(type.getLength() - 1));
                            createData(address, type);
                        }
                    }
                    count++;
                }
                catch (Exception ignored) { }
            }
        }
        return count;
    }

    private static BufferedReader reader(File file) throws Exception {
        return new BufferedReader(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8));
    }

    private static String decode(String value) {
        return new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8);
    }

    private static long seconds(long started) {
        return (System.currentTimeMillis() - started) / 1000;
    }
}
