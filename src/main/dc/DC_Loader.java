/* Copyright (C) Harry Clark */

/* SEGA Dreamcast GDI Tool for GHIDRA */

/* THIS FILE PERTAINS TO THE FUNCTIONALITY OF LOADING THE INNATE */
/* CONTENTS OF THE GDI ROM RESPECTIVELY */

/* THIS IS BY INTIALISING THE BYTEWISE VALUE OF THE IRQ MASKS */
/* TO CHECK FOR THE ROM WHEN PUT INTO THE CONSOLE USING THE */
/* VECTOR TABLE */

/* SEE SEGA DREAMCAST HARDWARE SPECIFICATION SECTION 6: */
/* https://segaretro.org/images/8/8b/Dreamcast_Hardware_Specification_Outline.pdf#page=35 */

package main.dc;

/* NESTED INCLUDES */

import java.io.*;
import java.util.*;

/* GHIDRA INCLUDES */

import ghidra.app.util.Option;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;

public class DC_Loader
{
    /* SEEK VALUES FOR VECTOR TABLE HEADER CHECKSUM */

    public static int SEEK_SET = 0;
    public static int SEEK_CUR = 1;
    public static int SEEK_END = 2;

    /* DE FACTO STANDARD HEX VALUES FOR CD-ROMS  */

    public static long DC_BASE = 0x20000000;
    public static long DC_INIT = 0x80000000;
    public static final long DC_BASE_ADDR = DC_BASE + 0x1000;
    public static String DC_LOADER = "DREAMCAST GDI LOADER";
    public static String DC_ID = "HKIT 3030";

    public DC_GDRom GDI;

    /* DEFINE THE CONSTANT BYTE OF THE INTERRUPT MASK IRQ */
    /* THIS WORKS BY TAKING INTO ACCOUNT THE LOWER BYTES ON THE CPU */
    /* WHICH PARSES INFORMATION BACK AND FORTH FROM THE GD DRIVE */

    /* SECTION TABLE 5 - PAGE 32: https://retrocdn.net/images/6/61/SH-4_32-bit_CPU_Core_Architecture.pdf#page=32 */
    /* https://mc.pp.se/dc/files/h14th002d2.pdf#page=31 */

    public static byte[] IMASK_LEVEL = new byte[]
    {
        0x00, 0x00, 0x00, 0x0C,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x0C, 
        0x01, 0x00, 0x00, 0x0C, 
        0x00, 0x00, 0x00, 0x0C,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    /* DEFINE THE CONSTANT BYTE OF THE PROGRAM COUNTER */
    /* THIS PARSES THROUGH THE CONTENTS OF THE SIG SCAN */
    /* TO VALIDATE THE 32 BIT LENGTH OF THE CONDITIONS BEING RUN */

    public static byte[] SPC_SIG_SCAN = new byte[]
    {
        (byte)0x3F8, (byte)0x3F8, (byte)0x3F8, (byte)0x3F8,
        0x00, 0x00, 0x00, (byte)0x00,
        (byte)0x3FC, (byte)0x3Fc, (byte)0x3Fc, (byte)0x3FC,
        (byte)0x04, (byte)0x04, (byte)0x04, (byte)0x04, 
    };
    

    /* RETURN THE NAME OF THE PLUGIN LOADER */

    public static String GET_BASE_NAME()
    {
        return DC_LOADER;
    }

    /* THIS FUNCTIONS PERTAINS TO THE WAY IN WHICH THE GHIDRA BINARY READER */
    /* WILL PARSE THE INFORMATION. THIS DETERMINES THE INITIALISATION OF THE BINARY READER */
    /* AND WILL LOAD THE CORRESPONDENCE FROM THE DISK */

    public Collection<LoadSpec> LOAD_SPECIFICATION(ByteProvider BYTE, BinaryReader BINARY) throws IOException
    {
        /* CONCATENATE A NEW LIST FROM THE LOAD SPECIFICATION FUNCTION CALL FROM GHIDRA */
        /* ACCORDING TO OFFICIAL GHIDRA DOCS, THIS LOOKS FOR THE DESIGNATED PRE-COMPILER LOADER */
        /* AS WELL AS LOOKING FOR THE BASE OF THE IMAGE TO DETERMINE HOW IT CAN BE DECOMPILED */

        /* SEE: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/java/ghidra/app/util/opinion/LoadSpec.java */

        List<LoadSpec> NEW_SPECS = new ArrayList<>();
        BINARY = new BinaryReader(BYTE, true);

        GDI = new DC_GDRom(BINARY); // USE GDI CONSTRUCTOR TO INSTANTIATE A NEW INSTANCE ACCORDING TO THE BINARY READER

        if (DC_GDRom.DATA_PARSED)
        {
            NEW_SPECS.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(DC_ID, "default"), true));
        }

        return NEW_SPECS;

    }

    /* LOCALLY DECLARED CONSTRUCTOR FOR READING THE CONTENTS OF THE HEADER */

    public GDI(BinaryReader READER)
    {
        this.READ_HEADER(READER);
    }

    /* BEGIN TO READ THE CONTENTS OF THE 8 BITWISE LENGTH OF THE HEADER */
    /* ESTABLISH THE TEXT OFFSET POINTER READER TO THE ORIGIN */

    private static void READ_HEADER(BinaryReader READER, GDI GDI)
    {
        try 
        {            
            READER.setPointerIndex(0);

            for (int i = 0; i < 7; i++)
            {
               GDI.OFFSETS.TEXT_OFFSET[i] += READER.readNextUnsignedInt();
               GDI.OFFSETS.TEXT_MEM_ADDR[i] += READER.readNextUnsignedInt();
               GDI.OFFSETS.TEXT_SIZE[i] += READER.readNextUnsignedInt();
            }

            for (int j = 0; j < 11; j++)
            {
                GDI.OFFSETS.DATA_OFFSET[j] += READER.readNextUnsignedInt();
                GDI.OFFSETS.DATA_MEM_ADDR[j] += READER.readNextUnsignedInt();
                GDI.OFFSETS.DATA_SIZE[j] += READER.readNextUnsignedInt();
            }

            GDI.OFFSETS.BSS_MEM_ADDR += READER.readNextUnsignedInt();
            GDI.OFFSETS.BSS_SIZE += READER.readNextUnsignedInt();
            GDI.OFFSETS.BSS_ENTRY += READER.readNextUnsignedInt();
            GDI.OFFSETS.HAS_BSS += true;
        } 
        
        catch (Exception e)  
        {
            throw new IOException(this, "GDI HEADER failed to read");
        }
    }    
}
