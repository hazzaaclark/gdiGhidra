/* Copyright (C) Harry Clark */

/* SEGA Dreamcast GDI Tool for GHIDRA */

/* THIS FILE PERTAINS TO THE FUNCTIONALITY OF LOADING THE INNATE */
/* CONTENTS OF THE GDI ROM RESPECTIVELY */

/* THIS IS BY INTIALISING THE BYTEWISE VALUE OF THE IRQ MASKS */
/* TO CHECK FOR THE ROM WHEN PUT INTO THE CONSOLE USING THE */
/* VECTOR TABLE */

/* SEE SEGA DREAMCAST HARDWARE SPECIFICATION SECTION 6: */
/* https://segaretro.org/images/8/8b/Dreamcast_Hardware_Specification_Outline.pdf#page=35 */

package gdi;

/* NESTED INCLUDES */

import java.io.*;
import java.util.*;

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

    private static final LanguageID CPU_ID = new LanguageID("SUPERH4:LE:32:default");
    private static final CompilerSpecID CPU_SPEC_ID = new CompilerSpecID("default");

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

        // ASSUMES THE BITWISE LENGTH OF READING FROM 16 BIT AND 32 BIT REGISTERS
        // RELATIVE TO A 2KB FLAG

        int[] READER_SIZE = {16 * 2048, 32 * 2048};

        READER_LEN += READER.length();

        // PROVIDED AN ARBITARY VALUE TO REPRESENT THE READER SIZE
        // ASSUME THAT THE SIZE MATCHES, LOAD THE SPECIFIED SPECS FROM THE BINARY

        for (int SIZES : READER_SIZE)
        {
            LOAD_SPECS.add(new LoadSpec(null, READER_LEN, null, false));
        }

        return LOAD_SPECS;
    }
}
