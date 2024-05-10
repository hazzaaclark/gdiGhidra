/* COPYRIGHT (C) HARRY CLARK 2024 */

/* SEGA DREAMCAST GDI TOOL FOR GHIDRA */

/* THIS FILE PERTAINS TO THE FUNCTIONALITY OF LOADING THE INNATE */
/* CONTENTS OF THE GDI ROM RESPECTIVELY */

/* THIS IS BY INTIALISING THE BYTEWISE VALUE OF THE IRQ MASKS */
/* TO CHECK FOR THE ROM WHEN PUT INTO THE CONSOLE USING THE */
/* VECTOR TABLE */

/* SEE SEGA DREAMCAST HARDWARE SPECIFICATION SECTION 6: */
/* https://segaretro.org/images/8/8b/Dreamcast_Hardware_Specification_Outline.pdf#page=35 */

package gdi;

/* NESTED INCLUDES */

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/* GHIDRA INCLUDES */

import ghidra.app.util.Option;
import ghidra.framework.options.Options;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.database.DBCachedObjectStoreFactory.LongDBFieldCodec;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;

public class DC_Loader extends AbstractLibrarySupportLoader
{
    /* SEEK VALUES FOR VECTOR TABLE HEADER CHECKSUM */

    public static DC_GDRom GDI;
    public static int SEEK_SET = 0;
    public static int SEEK_CUR = 1;
    public static int SEEK_END = 2;

    /* DE FACTO STANDARD HEX VALUES FOR CD-ROMS  */

    public static long DC_BASE_ADDRESS = 0x20000000;
    public static long DC_INIT = 0x80000000;
    public static long DC_BASE_ADDR = DC_BASE_ADDRESS + 0x1000;
    public static final String DC_LOADER = "DREAMCAST GDI LOADER";
    public static final String DC_ID = "HKIT 3030";
    private static final String DC_OPTION_NAME = "DREAMCAST OPTIONS: ";

    protected static final long RAM_KB = 1024;
    protected static final long RAM_MB = RAM_KB * RAM_KB;
    public static long DC_ENTRY_POINT; 
    public static long DC_VBR_ENTRY = 0x8C00F4000L;
    public static long SIZE;
    public static final long VBR_EXCEPTION = DC_VBR_ENTRY + 0x100;
    public static final long TLB_EXCEPTION = DC_VBR_ENTRY + 0x400;
    public static final long IRQ_EXCEPTION = DC_VBR_ENTRY + 0x600;

    private static final LanguageID CPU_ID = new LanguageID("SUPERH4:LE:32:default");
    private static final CompilerSpecID CPU_SPEC_ID = new CompilerSpecID("default");

    private static final ArrayList<Option> SEGMENT_OPTIONS = new ArrayList<Option>();
    private static Program PROGRAM_BASE;
    private static TaskMonitor TASK_MONITOR;
    private static BinaryReader READER;
    private static InputStream INPUT_STREAM;
    
    /* RETURN THE NAME OF THE PLUGIN LOADER */

    @Override
    public String getName()
    {
        return DC_LOADER;
    }


    /* THIS FUNCTIONS PERTAINS TO THE WAY IN WHICH THE GHIDRA BINARY READER */
    /* WILL PARSE THE INFORMATION. THIS DETERMINES THE INITIALISATION OF THE BINARY READER */
    /* AND WILL LOAD THE CORRESPONDENCE FROM THE DISK */

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider BYTE) throws IOException
    {
        /* CONCATENATE A NEW LIST FROM THE LOAD SPECIFICATION FUNCTION CALL FROM GHIDRA */
        /* ACCORDING TO OFFICIAL GHIDRA DOCS, THIS LOOKS FOR THE DESIGNATED PRE-COMPILER LOADER */
        /* AS WELL AS LOOKING FOR THE BASE OF THE IMAGE TO DETERMINE HOW IT CAN BE DECOMPILED */

        /* SEE: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/java/ghidra/app/util/opinion/LoadSpec.java */

        List<LoadSpec> LOAD_SPECS = new ArrayList<>();

        BinaryReader READER = new BinaryReader(BYTE, true);

        SIZE = READER.length();

        if(SIZE == RAM_MB || SIZE == RAM_MB * 2)
        {
            LOAD_SPECS.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(CPU_ID, CPU_SPEC_ID), true));
        }

        return LOAD_SPECS;
    }

    /* LOAD THE SUPPORTED SEGMENTS BASED ON A COUROUTINE CHECK FROM THE API */
    /* SUCH THAT IT IS ABLE TO RECONGISE THE STREAM OF MEMORY FROM THE ROM */

    @Override
    protected void load(ByteProvider PROVIDER, LoadSpec LOAD_SPEC, List<Option> OPTIONS, Program PROGRAM, TaskMonitor MONITOR, MessageLog LOG) throws CancelledException, IOException
    {
        FlatProgramAPI FPA = new FlatProgramAPI(PROGRAM_BASE);

        CREATE_SEGMENTS(FPA, LOG);
        GDI.CREATE_BASE_SEGMENT(FPA, INPUT_STREAM, "ROM", 0xA000000L, DC_BASE_ADDR, false, false, LOG);
        GDI.CREATE_BASE_SEGMENT(FPA, INPUT_STREAM, "FLASH_ROM", 0xA02000000L, DC_BASE_ADDR, true, false, LOG);
        GDI.CREATE_BASE_SEGMENT(FPA, INPUT_STREAM, "VRAM64", 0x84000000L, DC_BASE_ADDR, false, false, LOG);
        GDI.CREATE_BASE_SEGMENT(FPA, INPUT_STREAM, "VRAM32", 0x85000000L, DC_BASE_ADDR, false, false, LOG);

        INPUT_STREAM = PROVIDER.getInputStream(0L);
        GDI.CREATE_BASE_SEGMENT(FPA, INPUT_STREAM, "BASE", DC_BASE_ADDR, DC_BASE_ADDRESS, false, false, LOG);

        /* AFTER ALL OF THE ABOVE PRE-REQUISITES HAVE BEEN ESTABLISHED */
        /* THE ABSTRACT LOADER WILL NOW BEGIN TO INITIALISE THE ENTRY POINT */
        /* OF THE ROM USING FPA */

        /* DREAMCAST BASE ENTRY POINT */

        FPA.addEntryPoint(FPA.toAddr(DC_ENTRY_POINT));
        FPA.createFunction(FPA.toAddr(DC_ENTRY_POINT), "DC_ENTRY");

        /* ADDITIONAL VECTOR BASED REGISTER ENTRIES */
        /* NEEDED FOR THE VECTOR TABLE IN THE HEADER */

        FPA.addEntryPoint(FPA.toAddr(VBR_EXCEPTION));
        FPA.createFunction(FPA.toAddr(VBR_EXCEPTION), "DC_VBR_EXCEPTION");

        FPA.addEntryPoint(FPA.toAddr(TLB_EXCEPTION));
        FPA.createFunction(FPA.toAddr(TLB_EXCEPTION), "DC_TLB_EXCEPTION");

        FPA.addEntryPoint(FPA.toAddr(IRQ_EXCEPTION));
        FPA.createFunction(FPA.toAddr(IRQ_EXCEPTION), "DC_IRQ_EXCEPTION");
    }

    public static void CREATE_SEGMENTS(FlatProgramAPI FPA, MessageLog LOG) throws IOException
    {
        GDI.CCR_SEGMENTS(FPA, LOG);
        GDI.UBC_SEGMENTS(FPA, LOG);
        GDI.BSC_SEGMENTS(FPA, LOG);
        GDI.DMA_SEGMENTS(FPA, LOG);
        GDI.CPG_SEGMENTS(FPA, LOG);
        GDI.RTC_SEGMENTS(FPA, LOG);
        GDI.INTC_SEGMENTS(FPA, LOG);
        GDI.TMU_SEGMENTS(FPA, LOG);
        GDI.SCI_SEGMENTS(FPA, LOG);
        GDI.SCIF_SEGMENTS(FPA, LOG);
        GDI.HUDI_SEGMENTS(FPA, LOG);
    }

    /* LOAD THE DEFAULT OPTIONS UPON LOADING A ROM */
    /* IN THE CASE OF GHIDRA, THIS WILL PROMPT THE USER WILL APPLYING THE NECESSARY CONFIGURATIONS TO LOAD */
    /* THE CORRESPONDING TYPES */

    @Override
    public List<Option> getDefaultOptions(ByteProvider BYTE_PROVIDER, LoadSpec LOAD_SPEC, DomainObject DOMAIN, boolean IS_LOADED)
    {  
        /* ACCESS THE DEFAULT OPTIONS USING THE SUPER APPEND METHOD */ 
        /* IN THIS CONTEXT, THIS ALLOWS THE PROGRAM TO INHERIT THE METHOS FROM */
        /* THIS FUNCTION TO USE ELSEWHERE */

        List<Option> DEFAULT_LIST = new ArrayList<>();

        DEFAULT_LIST.add(new DC_Base(DC_OPTION_NAME, DC_VBR_ENTRY, DC_Base.class, COMMAND_LINE_ARG_PREFIX + ""));

        return DEFAULT_LIST;
    }

    /* VALIDATE THE PROVIDED OPTIONS IN RELATION TO THE CORRESPONDENCE OF THE ROM */
    /* DECODE THE LENGTH OF THE RAM BASE BY SENDING A STRING CAST RELATED TO THE DESIGNATED OPTION */

    @Override
    public String validateOptions(ByteProvider PROVIDER, LoadSpec LOAD_SPEC, List<Option> OPTIONS, Program PROGRAM)
    {
        String OPTION_NAME;

        for(Option OPTION : OPTIONS)
        {
            OPTION_NAME = OPTION.getName();

            if(OPTION_NAME.equals(DC_OPTION_NAME))
            {
                DC_BASE_ADDR = Long.decode((String)OPTION.getValue());
                break;
            }
        }

        return null;
    }
} 
