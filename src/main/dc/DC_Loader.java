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

import org.apache.commons.lang3.ObjectUtils.Null;

/* GHIDRA INCLUDES */

import ghidra.app.util.Option;
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
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class DC_Loader 
{
    /* SEEK VALUES FOR VECTOR TABLE HEADER CHECKSUM */

    public static DC_GDRom GDI;
    public static int SEEK_SET = 0;
    public static int SEEK_CUR = 1;
    public static int SEEK_END = 2;

    /* DE FACTO STANDARD HEX VALUES FOR CD-ROMS  */

    public static long DC_BASE = 0x20000000;
    public static long DC_INIT = 0x80000000;
    public static final long DC_BASE_ADDR = DC_BASE + 0x1000;
    public static final String DC_LOADER = "DREAMCAST GDI LOADER";
    public static final String DC_ID = "HKIT 3030";
    public static long DC_ENTRY_POINT; 
    public static long DC_VBR_ENTRY = 0x8C00F4000L;

    private static final LanguageID CPU_ID = new LanguageID("SUPERH4:LE:32:default");
    private static final CompilerSpecID CPU_SPEC_ID = new CompilerSpecID("default");

    private static final ArrayList<Option> SEGMENT_OPTIONS = new ArrayList<Option>();
    private static Program PROGRAM_BASE;
    private static TaskMonitor TASK_MONITOR;
    private static BinaryReader READER;
    private static InputStream INPUT_STREAM;
    
    /* RETURN THE NAME OF THE PLUGIN LOADER */

    public static String GET_BASE_NAME()
    {
        return DC_LOADER;
    }

    /* LOCALLY DECLARED CONSTRUCTOR FOR READING THE CONTENTS OF THE HEADER */
    
    public static void CONSTRUCT_ROM(BinaryReader READER)
    {
        READ_HEADER(READER, GDI);
    }

    /* THIS FUNCTIONS PERTAINS TO THE WAY IN WHICH THE GHIDRA BINARY READER */
    /* WILL PARSE THE INFORMATION. THIS DETERMINES THE INITIALISATION OF THE BINARY READER */
    /* AND WILL LOAD THE CORRESPONDENCE FROM THE DISK */

    public Collection<LoadSpec> LOAD_SPECIFICATION(ByteProvider BYTE)
    {
        BinaryReader BINARY = new BinaryReader(BYTE, true);

        /* CONCATENATE A NEW LIST FROM THE LOAD SPECIFICATION FUNCTION CALL FROM GHIDRA */
        /* ACCORDING TO OFFICIAL GHIDRA DOCS, THIS LOOKS FOR THE DESIGNATED PRE-COMPILER LOADER */
        /* AS WELL AS LOOKING FOR THE BASE OF THE IMAGE TO DETERMINE HOW IT CAN BE DECOMPILED */

        /* SEE: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/java/ghidra/app/util/opinion/LoadSpec.java */

        List<LoadSpec> NEW_SPECS = new ArrayList<>();
        BINARY = new BinaryReader(BYTE, true);

        CONSTRUCT_ROM(BINARY); // USE GDI CONSTRUCTOR TO INSTANTIATE A NEW INSTANCE ACCORDING TO THE BINARY READER

        LanguageCompilerSpecPair CPU_SPEC_PAIR = new LanguageCompilerSpecPair(CPU_ID, CPU_SPEC_ID);

        NEW_SPECS.add(new LoadSpec(null, 0, CPU_SPEC_PAIR, false));
        return NEW_SPECS;

    }

    /* READS THE CONTENTS OF THE HEADER */
    /* THIS IS ASSUMING THE ARBITARY CASES ARE IN PLACE SUCH AS TEXT AND DATA */

    /* THIS FUNCTION WILL LOOK OVER THE OFFSETS, MEMORY ADDRESSES, AND ARBITARY SIZE OF */
    /* EACH RESPECTIVE SECTION */

    private static void READ_HEADER(BinaryReader READER, DC_GDRom GDI) 
    {
        MessageLog LOG = new MessageLog();

        try 
        {            
            READER.setPointerIndex(0);

            for (int i = 0; i < 7; i++)
            {
               GDI.TEXT_OFFSET[i] = READER.readNextUnsignedInt();
               GDI.TEXT_MEM_ADDR[i] = READER.readNextUnsignedInt();
               GDI.TEXT_SIZE[i] = READER.readNextUnsignedInt();
            }

            for (int j = 0; j < 11; j++)
            {
                GDI.DATA_OFFSET[j] = READER.readNextUnsignedInt();
                GDI.DATA_MEM_ADDR[j] = READER.readNextUnsignedInt();
                GDI.DATA_SIZE[j] = READER.readNextUnsignedInt();
            }

            GDI.BSS_MEM_ADDR = READER.readNextUnsignedInt();
            GDI.BSS_SIZE = READER.readNextUnsignedInt();
            GDI.BSS_ENTRY = READER.readNextUnsignedInt();
            GDI.HAS_BSS = true;
        } 
        
        catch (Exception EXEC)  
        {
            LOG.appendException(EXEC);
        }
    }
    
    
    /* RUNS A COROUTINE CHECK TO DETERMINE THE CORRESPONDING LOAD SPECIFICATIONS */
    /* FROM THE DREAMCAST'S LANGUAGE COMPILER */

    public Collection<LoadSpec> LOAD_SUPPORTED_SPECS(ByteProvider BYTE_PROVIDER, BinaryReader READER, long READER_LEN) throws IOException
    {
        List<LoadSpec> LOAD_SPECS = new ArrayList<>();
        LanguageCompilerSpecPair CPU_SPEC_PAIR = new LanguageCompilerSpecPair(CPU_ID, CPU_SPEC_ID);

        // ASSUMES THE BITWISE LENGTH OF READING FROM 16 BIT AND 32 BIT REGISTERS
        // RELATIVE TO A 2KB FLAG

        int[] READER_SIZE = {16 * 2048, 32 * 2048};

        READER_LEN = READER.length();

        // PROVIDED AN ARBITARY VALUE TO REPRESENT THE READER SIZE
        // ASSUME THAT THE SIZE MATCHES, LOAD THE SPECIFIED SPECS FROM THE BINARY

        for (int SIZES : READER_SIZE)
        {
            LOAD_SPECS.add(new LoadSpec(null, READER_LEN, CPU_SPEC_PAIR, true));
        }

        return LOAD_SPECS;
    }

    /* LOAD THE SUPPORTED SEGMENTS BASED ON A COUROUTINE CHECK FROM THE API */
    /* SUCH THAT IT IS ABLE TO RECONGISE THE STREAM OF MEMORY FROM THE ROM */
    
    public static final void LOAD_SEGMENTS(ByteProvider BYTE_PROVIDER, LoadSpec LOAD_SPEC) throws IOException
    {
        MessageLog LOG = new MessageLog();
        FlatProgramAPI FPA = new FlatProgramAPI(PROGRAM_BASE);

        CREATE_SEGMENTS(FPA, LOG);
        GDI.CREATE_BASE_SEGMENT(FPA, INPUT_STREAM, "ROM", 0xA000000L, DC_BASE_ADDR, false, false, LOG);
        GDI.CREATE_BASE_SEGMENT(FPA, INPUT_STREAM, "FLASH_ROM", 0xA02000000L, DC_BASE_ADDR, true, false, LOG);
        GDI.CREATE_BASE_SEGMENT(FPA, INPUT_STREAM, "VRAM64", 0x84000000L, DC_BASE_ADDR, false, false, LOG);
        GDI.CREATE_BASE_SEGMENT(FPA, INPUT_STREAM, "VRAM32", 0x85000000L, DC_BASE_ADDR, false, false, LOG);

        INPUT_STREAM = BYTE_PROVIDER.getInputStream(0L);
        GDI.CREATE_BASE_SEGMENT(FPA, INPUT_STREAM, "BASE", DC_BASE_ADDR, DC_BASE, false, false, LOG);

        /* AFTER ALL OF THE ABOVE PRE-REQUISITES HAVE BEEN ESTABLISHED */
        /* THE ABSTRACT LOADER WILL NOW BEGIN TO INITIALISE THE ENTRY POINT */
        /* OF THE ROM USING FPA */

        /* DREAMCAST BASE ENTRY POINT */

        FPA.addEntryPoint(FPA.toAddr(DC_ENTRY_POINT));
        FPA.createFunction(FPA.toAddr(DC_ENTRY_POINT), "DC_ENTRY");

        /* ADDITIONAL VECTOR BASED REGISTER ENTRIES */
        /* NEEDED FOR THE VECTOR TABLE IN THE HEADER */

        long VBR_EXCEPTION = DC_VBR_ENTRY + 0x100;

        FPA.addEntryPoint(FPA.toAddr(VBR_EXCEPTION));
        FPA.createFunction(FPA.toAddr(VBR_EXCEPTION), "DC_VBR_EXCEPTION");

        long TLB_EXCEPTION = DC_VBR_ENTRY + 0x400;

        FPA.addEntryPoint(FPA.toAddr(TLB_EXCEPTION));
        FPA.createFunction(FPA.toAddr(TLB_EXCEPTION), "DC_TLB_EXCEPTION");

        long IRQ_EXCEPTION = DC_VBR_ENTRY + 0x600;

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

    public static List<Option> GET_DEFAULT_OPTIONS(ByteProvider BYTE_PROVIDER, LoadSpec LOAD_SPEC, DomainObject DOMAIN)
    {  
        /* ACCESS THE DEFAULT OPTIONS USING THE SUPER APPEND METHOD */ 
        /* IN THIS CONTEXT, THIS ALLOWS THE PROGRAM TO INHERIT THE METHOS FROM */
        /* THIS FUNCTION TO USE ELSEWHERE */

        List<Option> DEFAULT_LIST = GET_DEFAULT_OPTIONS(BYTE_PROVIDER, LOAD_SPEC, DOMAIN);

        SEGMENT_OPTIONS.add(new Option(DC_ID, DC_BASE_ADDR));
        SEGMENT_OPTIONS.add(new Option(Long.toString(DC_VBR_ENTRY), 16));
        return DEFAULT_LIST;
    }
}
