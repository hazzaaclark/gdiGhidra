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
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DC_Loader extends DC_GDRom
{
    /* SEEK VALUES FOR VECTOR TABLE HEADER CHECKSUM */

    public static int SEEK_SET = 0;
    public static int SEEK_CUR = 1;
    public static int SEEK_END = 2;
    public static int SEEK_TYPE;

    /* DE FACTO STANDARD HEX VALUES FOR CD-ROMS  */

    public static long DC_INIT = 0x80000000;
    private static final long RAM_SIZE = 0x02000000L;
    public static final String DC_ID = "HKIT 3030";
    private static final String DC_OPTION_NAME = "DREAMCAST OPTIONS: ";

    protected static final long RAM_KB = 1024;
    protected static final long RAM_MB = RAM_KB * RAM_KB;
    public static long DC_ENTRY_POINT = 0x8C000000L;
    public static final long VBR_EXCEPTION = DC_ENTRY_POINT + 0x100;
    public static final long TLB_EXCEPTION = DC_ENTRY_POINT + 0x400;
    public static final long IRQ_EXCEPTION = DC_ENTRY_POINT + 0x600;
    
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
            /* CONCATENATE A NEW LIST FROM THE LOAD SPECIFICATION FUNCTION CALL FROM GHIDRA */
            /* ACCORDING TO OFFICIAL GHIDRA DOCS, THIS LOOKS FOR THE DESIGNATED PRE-COMPILER LOADER */
            /* AS WELL AS LOOKING FOR THE BASE OF THE IMAGE TO DETERMINE HOW IT CAN BE DECOMPILED */

            /* SEE: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/java/ghidra/app/util/opinion/LoadSpec.java */

            List<LoadSpec> LOAD_SPECS = new ArrayList<>();

            BinaryReader READER = new BinaryReader(BYTE, true);
        
            long SIZE = READER.length();

            if(SIZE == 16 * 1024 * 1024 || SIZE == 32 * 1024 * 1024)
            {
                LOAD_SPECS.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("SuperH4:LE:32:default", "default"), true));
            }

            return LOAD_SPECS;
        }

    /* LOAD THE SUPPORTED SEGMENTS BASED ON A COUROUTINE CHECK FROM THE API */
    /* SUCH THAT IT IS ABLE TO RECONGISE THE STREAM OF MEMORY FROM THE ROM */

    @Override
    protected void load(ByteProvider PROVIDER, LoadSpec LOAD_SPEC, List<Option> OPTIONS, Program PROGRAM, TaskMonitor MONITOR, MessageLog LOG) throws CancelledException, IOException
    {
        FlatProgramAPI FPA = new FlatProgramAPI(PROGRAM);

        CREATE_SEGMENTS(FPA, LOG);

        InputStream RAW_STREAM = PROVIDER.getInputStream(0L);
        DC_GDRom.CREATE_BASE_SEGMENT(FPA, RAW_STREAM, "RAM", DC_ENTRY_POINT, RAM_SIZE, true, true, LOG);
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
    /* IN THE CASE OF GHIDRA, THIS WILL PROMPT THE USER WILL APPLYING THE NECESSARY CONFIGURATIONS TO LOAD */
    /* THE CORRESPONDING TYPES */

    @Override
    public List<Option> getDefaultOptions(ByteProvider BYTE_PROVIDER, LoadSpec LOAD_SPEC, DomainObject DOMAIN, boolean IS_LOADED)
    {  
        /* ACCESS THE DEFAULT OPTIONS USING THE SUPER APPEND METHOD */ 
        /* IN THIS CONTEXT, THIS ALLOWS THE PROGRAM TO INHERIT THE METHOS FROM */
        /* THIS FUNCTION TO USE ELSEWHERE */

        List<Option> DEFAULT_LIST = new ArrayList<>();

        DEFAULT_LIST = super.getDefaultOptions(BYTE_PROVIDER, LOAD_SPEC, DOMAIN, IS_LOADED);
        return DEFAULT_LIST;
    }

    /* VALIDATE THE PROVIDED OPTIONS IN RELATION TO THE CORRESPONDENCE OF THE ROM */
    /* DECODE THE LENGTH OF THE RAM BASE BY SENDING A STRING CAST RELATED TO THE DESIGNATED OPTION */

    @Override
    public String validateOptions(ByteProvider PROVIDER, LoadSpec LOAD_SPEC, List<Option> OPTIONS, Program PROGRAM)
    {
        for(Option OPTION : OPTIONS)
        {
            String OPTION_NAME = OPTION.getName();

            if(OPTION_NAME.equals(DC_OPTION_NAME))
            {
                DC_INIT = Long.decode((String)OPTION.getValue());
                break;
            }
        }

        return super.validateOptions(PROVIDER, LOAD_SPEC, OPTIONS, PROGRAM);
    }
} 
