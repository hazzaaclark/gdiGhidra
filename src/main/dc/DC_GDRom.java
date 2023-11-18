/* Copyright (C) Harry Clark */

/* SEGA Dreamcast GDI Tool for GHIDRA */

/* THIS FILE PERTAINS TO THE FUNCTIONALITY OF LOADING THE INNATE */
/* CONTENTS OF THE GDI ROM RESPECTIVELY */

package main.dc;

/* NESTED INCLUDES */

import java.io.IOException;

/* GHIDRA INCLUDES */

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.*;

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

    public static class OFFSETS
    {
        public static long[] TEXT_OFFSET;
        public static long[] DATA_OFFSET;
        public static long[] TEXT_MEM_ADDR;
        public static long[] DATA_MEM_ADDR;
        public static long[] TEXT_SIZE;
        public static long[] DATA_SIZE;
        public static boolean HAS_BSS;
        public static long BSS_SIZE;
        public static long BSS_MEM_ADDR;
        public static long BSS_ENTRY;
    }

    /* ARBITARY DATA STRUCTURE TYPE NECESSARY FOR DETERMINING */
    /* THE CONTENTS OF THE HEADER */

    /* SUCH IS THE CASE WITH ANY EXECUTABLE, THE BINARY CONTENT IS BROKEN DOWN */
    /* INTO INITIALISATION, STACK POINTER NOTATION AND TEXT SEGMENTS */

    public static final String[] HEADER_NAMES =
    {
        ".init", ".text", ".text1", ".text2", ".text3", ".text4", ".text5"
    };

    public static final String[] DATA_TYPES = 
    {
        ".bss", ".sbss", 
    };

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
    
    /* CREATES THE NECESSARY SEGMENTS PERTAINING TOWARDS THE CPU'S DESIGANTED */
    /* REGISTERS AND TYPE - ALL OF WHICH WILL BE PARSED BY THE FPA */

    /* INSIDE OF THE OBJECT FUNCTIONS PERTAINING TOWARDS EACH OF THE CPU'S REGISTERS */
    /* THERE IS A CONSTRUCTOR RELATIVE TO EACH METHOD */

    /* THERE WILL BE LOCAL VARIABLES DENOTING THE FOLLOWING:
    /* THE API,
    /* THE INITIAL TERMINATOR VALUE */ 
    /* THE TYPE OF REGISTER */
    /* THE INITIAL STARTING ADDRESS */
    /* THE FLAG VALUE */
    /* AND BOOLEAN EXPRESSIONS TO DETERMINE WHETHER ALL OF THE ABOVE HAS BEEN ACCOUNTED FOR */

    private static final void CREATE_BASE_SEGMENT(FlatProgramAPI FPA, MessageLog LOG)
    {
        CCR_SEGMENTS(FPA, LOG);
        UBC_SEGMENTS(FPA, LOG);
    }

    /* CONDITION CODE REGISTER SEGMENTS */

    private static final void CCR_SEGMENTS()
    {
        CREATE_BASE_SEGMENT(FPA, null, "CCR", 0xFF000000, 0x48, true, false, LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF000000L, "CCN_PTEH", "Page Table Entry Address HI", log);
    }

    /* USER BREAK CONTROLLER SEGMENTS */

    private static final void UBC_SEGMENTS()
    {
    }

    /* CREATE AN ADDRESSIBLEE CONSTANT SUCH THAT IT WILL PARSE THE CONTENTS OF THE PROVIDED ADDRESS */
    /* THE FOLLOWING SEGMENT OF CODE ACTS AS A GLOBAL VARIABLE FOR ALL ADDRESS TYPE OF ANY GIVEN LENGTH */

    private static void CREATE_BITWISE_CONST(FlatProgramAPI FPA, long ADDRESS, String ADDRESS_NAME, String ADDRESS_TYPE, MessageLog LOG)
    {
        Address ADDRESS_ARG = FPA.toAddr(ADDRESS);

        /* FIRST OF ALL, BEFORE CREATING THE PROPRIATORY SEGMENTS */
        /* WE USED UNIT TESTING TO ENSURE THAT THE REQUIRED ARGS ARE BEING MET */
        /* IN RELATION TO WHAT THE API IS COMMUNICATING */

        try
        {
            FPA.createData(ADDRESS_ARG, "");
        }

        catch (IOException EXEC)
        {
            LOG.appendException(EXEC);
            return;
        }

        /* AFTER WHICH, WE CREATE THE DESIGNATED PAGE TABLE DESIGNATED FOR THE GIVEN ADDRESS */

        try
        {
            FPA.getCurrentProgram().getSymbolTable().createLabel(ADDRESS, ADDRESS_NAME, SourceType.IMPORTRED);
        }

        catch (IOException EXEC)
        {

        }
    }
}
