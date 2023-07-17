/* Copyright (C) Harry Clark */

/* SEGA Dreamcast GDI Tool for GHIDRA */

/* THIS FILE PERTAINS TO THE FUNCTIONALITY OF LOADING THE INNATE */
/* CONTENTS OF THE GDI ROM RESPECTIVELY */

package main.dc;

/* NESTED INCLUDES */

import java.io.IOException;

/* GHIDRA INCLUDES */

import ghidra.app.util.bin.BinaryReader;

public class DC_GDRom 
{
    public static final int HEADER_SIZE = 0x800;
    public static final long PC_INIT = 0x10;
    public static final long GP_INIT = 0x14;
    public static final long ROM_ADDR = 0x1C;
    public static final long DATA_ADDR = 0x20;
    public static final long SP_INIT = 0x30;
    public static final long SP_OFFSET = 0x31;
    public static boolean DATA_PARSED = false;

    /* SEE: https://mc.pp.se/dc/files/h14th002d2.pdf#page=31 */

    public static class FLAGS
    {
        public static final byte FPU_ERROR = 0x00;
        public static final byte NOP = 0x06;
        public static final byte ZERO = 0x05;
        public static final byte OVERFLOW = 0x04;
        public static final byte UNDERFLOW = 0x03;
        public static final byte INEXACT = 0x02;
    }

    public static long PC_INIT_CONSTRUCT = 0;
    public static long GP_INIT_CONSTRUCT = 0;
    public static long ROM_ADDR_CONSTRUCT = 0;
    public static long DATA_ADDR_CONSTRUCT = 0;
    public static long SP_INIT_CONSTRUCT = 0;
    public static long SP_OFFSET_CONSTRUCT = 0;

    /*  CONSTRUCTOR TO REFER BACK TO INSIDE OF THE MASTER LOADER'S FUNCTION CALLS */

    public DC_GDRom(BinaryReader BINARY) throws IOException
    {
        PARSE_DATA(BINARY);
    }

    /* PARSE THE DATA RELATIVE TO THE HITACHI S4'S FUNCTIONALITY */
    /* THIS TAKES INTO ACCOUNT THE 32 BITWISE LENGTH OF THE CPU */
    /* AND THEIR RESPECTIVE REGISTERS AND THEIR INNATE FUNCTIONS */

    public static void PARSE_DATA(BinaryReader BINARY) throws IOException
    {
        if(BINARY.length() < HEADER_SIZE) return;

        PC_INIT_CONSTRUCT = BINARY.readUnsignedInt(PC_INIT);
        GP_INIT_CONSTRUCT = BINARY.readUnsignedInt(GP_INIT);
        ROM_ADDR_CONSTRUCT = BINARY.readUnsignedInt(ROM_ADDR);
        DATA_ADDR_CONSTRUCT = BINARY.readUnsignedInt(DATA_ADDR);
        SP_INIT_CONSTRUCT = BINARY.readUnsignedInt(SP_INIT);
        SP_OFFSET_CONSTRUCT = BINARY.readUnsignedInt(SP_OFFSET);

        DATA_PARSED = true;
    }
}
