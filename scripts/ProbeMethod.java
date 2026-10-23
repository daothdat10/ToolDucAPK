//@category DucAPK

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class ProbeMethod extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address address = currentProgram.getImageBase().add(62947860L);
        println("PROBE imageBase=" + currentProgram.getImageBase() + " address=" + address);
        println("PROBE memory=" + currentProgram.getMemory().contains(address));
        println("PROBE instructionBefore=" + getInstructionAt(address));
        println("PROBE disassemble=" + disassemble(address));
        Function function = getFunctionAt(address);
        if (function == null) {
            function = createFunction(address, "ProbeMethod");
        }
        println("PROBE function=" + function);
        if (function != null) {
            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(currentProgram);
            DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
            println("PROBE completed=" + result.decompileCompleted());
            if (result.getDecompiledFunction() != null) {
                String code = result.getDecompiledFunction().getC();
                println("PROBE code=" + code.substring(0, Math.min(code.length(), 1000)));
            }
            decompiler.dispose();
        }
    }
}
