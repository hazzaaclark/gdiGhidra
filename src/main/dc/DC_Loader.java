/* COPYRIGHT (C) HARRY CLARK 2024 */

/* SEGA DREAMCAST GDI TOOL FOR GHIDRA */

/* THIS FILE PERTAINS TO THE FUNCTIONALITY OF LOADING THE INNATE */
/* CONTENTS OF THE GDI ROM RESPECTIVELY */

/* THIS IS BY INTIALISING THE BYTEWISE VALUE OF THE IRQ MASKS */
/* TO CHECK FOR THE ROM WHEN PUT INTO THE CONSOLE USING THE */
/* VECTOR TABLE */

/* SEE SEGA DREAMCAST HARDWARE SPECIFICATION SECTION 6: */
/* https://segaretro.org/images/8/8b/Dreamcast_Hardware_Specification_Outline.pdf#page=35 */

/* 12/05/24 - USEFUL LINKS I FEEL AS THOUGH WOULD BE USEFUL IN DUE COURSE */
/* https://segaretro.org/images/7/78/DreamcastDevBoxSystemArchitecture.pdf  */
/* https://segaretro.org/ROM_header#Dreamcast */

package gdi;

/* NESTED INCLUDES */

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/* GHIDRA INCLUDES */

import ghidra.program.model.address.Address;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DC_Loader extends DC_GDRom
{
    public static final int DC_INVALID = -1;
    public static final int DC_GDI = 0;
    public static int DC_LOAD_TYPE = DC_INVALID;

    /* DE FACTO STANDARD HEX VALUES FOR CD-ROMS  */

    public static long DC_INIT = 0x80000000;
    private static final long RAM_SIZE = 0x02000000L;
    public static final String DC_ID = "HKIT 3030";
    private static final String DC_OPTION_NAME = "DREAMCAST OPTIONS: ";

    protected static final long RAM_KB = 1024;
    protected static final long RAM_MB = RAM_KB * RAM_KB;

    public static long DC_ENTRY_POINT = 0x8C000000L;
    
    /* RETURN THE NAME OF THE PLUGIN LOADER */

    @Override
    public String getName()
    {
        return "Dreamcast GDI Loader";
    }

    /* THIS FUNCTIONS PERTAINS TO THE WAY IN WHICH THE GHIDRA BINARY READER */
    /* WILL PARSE THE INFORMATION. THIS DETERMINES THE INITIALISATION OF THE BINARY READER */
    /* AND WILL LOAD THE CORRESPONDENCE FROM THE DISK */

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider BYTE) throws IOException
    {
        List<LoadSpec> LOAD_SPECS = new ArrayList<>();

        /* FIRST AND FOREMOST, CHECK TO DETERMINE THE CORRESPONDING FILE EXTENSION */

        if(IS_DREAMCAST_ROM(BYTE))
        {
            DC_LOAD_TYPE = DC_GDI;
        }

        /* CONCATENATE A NEW LIST FROM THE LOAD SPECIFICATION FUNCTION CALL FROM GHIDRA */
        /* ACCORDING TO OFFICIAL GHIDRA DOCS, THIS LOOKS FOR THE DESIGNATED PRE-COMPILER LOADER */
        /* AS WELL AS LOOKING FOR THE BASE OF THE IMAGE TO DETERMINE HOW IT CAN BE DECOMPILED */

        /* SEE: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/java/ghidra/app/util/opinion/LoadSpec.java */

        if(DC_LOAD_TYPE != DC_INVALID)
        {
            LOAD_SPECS.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("SuperH4:LE:32:default", "default"), true));
        }

        return LOAD_SPECS;
    }

    /* BRUTE FORCE ARBITRARY CHECKER TO DETERMINE IF THE FILE EXT IS A REAL DREAMCAST ROM */
    /* BASED ON THE HARDWARE IDENTIFIER */
    
    public boolean IS_DREAMCAST_ROM(ByteProvider PROVIDER) throws IOException
    {
        String SEGA_SIGNATURE = "SEGA SEGAKATANA";

        if(PROVIDER.length() >= SEGA_SIGNATURE.length())
        {
            byte[] SIGNATURE = PROVIDER.readBytes(0, SEGA_SIGNATURE.length());

            if(Arrays.equals(SIGNATURE, SEGA_SIGNATURE.getBytes()))
            {
                return true;
            }
        }

        return false;
    }

    /* LOAD THE SUPPORTED SEGMENTS BASED ON A COUROUTINE CHECK FROM THE API */
    /* SUCH THAT IT IS ABLE TO RECONGISE THE STREAM OF MEMORY FROM THE ROM */

    @Override
    protected void load(ByteProvider PROVIDER, LoadSpec LOAD_SPEC, List<Option> OPTIONS, Program PROGRAM, TaskMonitor MONITOR, MessageLog LOG) throws CancelledException, IOException
    {
        FlatProgramAPI FPA = new FlatProgramAPI(PROGRAM);

        CREATE_SEGMENTS(FPA, LOG);

        InputStream RAW_STREAM = PROVIDER.getInputStream(0L);
        DC_GDRom.CREATE_SEGMENT(FPA, RAW_STREAM, "RAM", DC_ENTRY_POINT, RAM_SIZE, true, true, LOG);
    }

    public static void CREATE_SEGMENTS(FlatProgramAPI FPA, MessageLog LOG) 
    {
        DC_GDRom.CCR_SEGMENTS(FPA, LOG);
        DC_GDRom.UBC_SEGMENTS(FPA, LOG);
        DC_GDRom.BSC_SEGMENTS(FPA, LOG);
        DC_GDRom.DMA_SEGMENTS(FPA, LOG);
        DC_GDRom.CPG_SEGMENTS(FPA, LOG);
        DC_GDRom.RTC_SEGMENTS(FPA, LOG);
        DC_GDRom.INTC_SEGMENTS(FPA, LOG);
        DC_GDRom.TMU_SEGMENTS(FPA, LOG);
        DC_GDRom.SCI_SEGMENTS(FPA, LOG);
        DC_GDRom.SCIF_SEGMENTS(FPA, LOG);
        DC_GDRom.HUDI_SEGMENTS(FPA, LOG);
    }

    /* LOAD THE DEFAULT OPTIONS UPON LOADING A ROM */
    /* IN THE CASE OF GHIDRA, THIS WILL PROMPT THE USER WILL APPLYING TH    E NECESSARY CONFIGURATIONS TO LOAD */
    /* THE CORRESPONDING TYPES */

    @Override
    public List<Option> getDefaultOptions(ByteProvider BYTE_PROVIDER, LoadSpec LOAD_SPEC, DomainObject DOMAIN, boolean IS_LOADED)
    {  
        /* ACCESS THE DEFAULT OPTIONS USING THE SUPER APPEND METHOD */ 
        /* IN THIS CONTEXT, THIS ALLOWS THE PROGRAM TO INHERIT THE METHOS FROM */
        /* THIS FUNCTION TO USE ELSEWHERE */

        List<Option> DEFAULT_LIST = super.getDefaultOptions(BYTE_PROVIDER, LOAD_SPEC, DOMAIN, IS_LOADED);
        return DEFAULT_LIST;
    }

    /* VALIDATE THE PROVIDED OPTIONS IN RELATION TO THE CORRESPONDENCE OF THE ROM */
    /* DECODE THE LENGTH OF THE RAM BASE BY SENDING A STRING CAST RELATED TO THE DESIGNATED OPTION */

    @Override
    public String validateOptions(ByteProvider PROVIDER, LoadSpec LOAD_SPEC, List<Option> OPTIONS, Program PROGRAM)
    {
        return super.validateOptions(PROVIDER, LOAD_SPEC, OPTIONS, PROGRAM);
    }

    /* CREATE A MEMORY MAP REGION IN RELATION TO THE CORRESPONDENCE OF THE CPU AND CONSOLE */

    public void CREATE_MEMORY_REGION(String MAP_NAME, long START_ADDR, long END_ADDR, boolean READ, boolean WRITE, boolean EXECUTE, Program PROGRAM, TaskMonitor MONITOR, MessageLog LOG)
    {
        try
        {
            Address ADDR;
            MemoryBlock MEM;

            MAP_NAME = MAP_NAME.replaceAll("\\s+","_");

            ADDR = PROGRAM.getAddressFactory().getDefaultAddressSpace().getAddress(START_ADDR);
            MEM = PROGRAM.getMemory().createInitializedBlock(MAP_NAME, ADDR, END_ADDR-START_ADDR, (byte)0x00, MONITOR, false);
            MEM.setRead(READ);
            MEM.setWrite(WRITE);
            MEM.setExecute(EXECUTE);

        }

        catch(Exception E)
        {
            LOG.appendException(E);
        }
    }
} 
