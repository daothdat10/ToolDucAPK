//@category DucAPK

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class FindXrefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) throw new IllegalArgumentException("Expected one or more target RVAs");
        for (String arg : args) {
            long rva = Long.decode(arg);
            Address target = currentProgram.getImageBase().add(rva);
            println("XREF target=" + target + " imageBase=" + currentProgram.getImageBase());
            ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(target);
            while (it.hasNext()) {
                Reference ref = it.next();
                Function caller = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                println("XREF " + ref.getFromAddress() + " type=" + ref.getReferenceType() +
                    " caller=" + (caller == null ? "<none>" : caller.getName() + " @ " + caller.getEntryPoint()));
            }
        }
    }
}
