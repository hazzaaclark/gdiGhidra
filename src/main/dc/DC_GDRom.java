/* Copyright (C) Harry Clark */

/* SEGA Dreamcast GDI Tool for GHIDRA */

/* THIS FILE PERTAINS TO THE FUNCTIONALITY OF LOADING THE INNATE */
/* CONTENTS OF THE GDI ROM RESPECTIVELY */

package gdi;

/* NESTED INCLUDES */

import java.io.IOException;
import java.io.InputStream;

/* GHIDRA INCLUDES */

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import ghidra.app.util.importer.MessageLog;

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

    private static BinaryReader READER;

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

    public DC_GDRom() throws IOException
    {
        PARSE_DATA();
    }

    /* PARSE THE DATA RELATIVE TO THE HITACHI S4'S FUNCTIONALITY */
    /* THIS TAKES INTO ACCOUNT THE 32 BITWISE LENGTH OF THE CPU */
    /* AND THEIR RESPECTIVE REGISTERS AND THEIR INNATE FUNCTIONS */

    public static void PARSE_DATA() throws IOException
    {
        if(READER.length() < HEADER_SIZE) return;

        PC_INIT_CONSTRUCT = READER.readUnsignedInt(PC_INIT);
        GP_INIT_CONSTRUCT = READER.readUnsignedInt(GP_INIT);
        ROM_ADDR_CONSTRUCT = READER.readUnsignedInt(ROM_ADDR);
        DATA_ADDR_CONSTRUCT = READER.readUnsignedInt(DATA_ADDR);
        SP_INIT_CONSTRUCT = READER.readUnsignedInt(SP_INIT);
        SP_OFFSET_CONSTRUCT = READER.readUnsignedInt(SP_OFFSET);

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

        /* FROM HERE, I AM ABLE TO ACCESS ALL OF THE PRE-REQUISITIES */
        /* ESTABLISHED IN THIS CORRESPONDING FILE */
        /* ALL WITHIN THE INTEREST OF BEING ABLE TO LOAD THESE SEGMENT STREAMS INTO THE API */

    public static void CREATE_BASE_SEGMENT(FlatProgramAPI FPA, InputStream STREAM, String NAME, long ADDRESS, long SIZE, boolean WRTIE, boolean EXEC, MessageLog LOG)
    {
        CCR_SEGMENTS(FPA, LOG);
        UBC_SEGMENTS(FPA, LOG);
        BSC_SEGMENTS(FPA, LOG);
        UBC_SEGMENTS(FPA, LOG);
        DMA_SEGMENTS(FPA, LOG);
        CPG_SEGMENTS(FPA, LOG);
    }

    /* CONDITION CODE REGISTER SEGMENTS */

    public static final void CCR_SEGMENTS(FlatProgramAPI FPA, MessageLog LOG)
    {
        CREATE_BASE_SEGMENT(FPA, null, "CCR", 0xFF000000L, 0x48, true, false, LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF000000L, "CCR_PTEH", "Page Table Entry Address HI", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF000004L, "CCR_PTEL", "Page Table Entry Address LO", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF000008L, "CCR_TTB", "Translation Table Base Register", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF00000CL, "CCR_TEA", "TLB Exception Address Register", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF000010L, "CCR_MEM", "MMU Control Register", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF000014L, "CCR_BASRA", "Break ASID Register A", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF000018L, "CCR_BASRB", "Break ASID Register B", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF00001CL, "CCR_BASE", "Condition Code Register", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF000020L, "CCR_TRA", "TRAP Register A Exception", LOG);
        CREATE_BITWISE_CONST(FPA, 0x00000024L, "CCR_EXEC_EVT", "Exception Event Register", LOG);
        CREATE_BITWISE_CONST(FPA, 0x00000028L, "CCR_INT_EVT", "Interrupt Event Register", LOG);
        CREATE_BITWISE_CONST(FPA, 0x00000030L, "CCR_PVR", "Processor Version Register", LOG);
        CREATE_BITWISE_CONST(FPA, 0x00000034L, "CCR_PTEA", "Page Table Entry Assistance Register", LOG);
        CREATE_BITWISE_CONST(FPA, 0x00000038L, "CCR_QACR0", "Queue Address Control Register 0", LOG);
        CREATE_BITWISE_CONST(FPA, 0x0000003CL, "CCR_QACR1", "Queue Address Control Register 1", LOG);
        CREATE_BITWISE_CONST(FPA, 0x00000044L, "CCR_PRR", "Product Register", LOG);
    }

    /* USER BREAK CONTROLLER SEGMENTS */

    public static final void UBC_SEGMENTS(FlatProgramAPI FPA, MessageLog LOG)
    {
        CREATE_BASE_SEGMENT(FPA, null, "UBC", 0xFF200000L, 0x24, true, false, LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF200000L, "UBC_BARA", "Break Address Register A", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF200004L, "UBC_BAMRA", "Break Address Mask Register A", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF200008L, "UBC_BBRA", "Break Bus Cycle Register A", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF20000CL, "UBC_BARB", "Break Address Register B", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF200010L, "UBC_BAMRB", "Break Address Mask Register B", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF200014L, "UBC_BBRB", "Break Bus Cycle Register B", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF200018L, "UBC_BDRB", "Break Data Register B", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF20001CL, "UBC_BDMRB", "Break Data Mask Register B", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF200020L, "UBC_BRCR", "Break Register Control", LOG);
    }

    /* BUS CONTROL SEGMENTS */

    private static final void BSC_SEGMENTS(FlatProgramAPI FPA, MessageLog LOG)
    {
        CREATE_BASE_SEGMENT(FPA, null, "BSC", 0xFF8000000L, 0x4C, true, false, LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF8000000L, "BSC_R1", "Bus Control Register 1", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF8000004L, "BSC_R2", "Bus Control Register 2", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF8000008L, "BSC_WCR1", "Wait Control Register 1", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF800000CL, "BSC_WCR2", "Wait Control Register 2", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF8000010L, "BSC_WCR3", "Wait Control Register 3", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF8000014L, "BSC_MCR", "Memory Control Register", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF8000018L, "BSC_PCR", "PCMIA Control Register", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF800001CL, "BSC_RTSCR", "Refresh Timer Control/State Register", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF8000020L, "BSC_RTCNT", "Refresh Timer Counter", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF8000024L, "BSC_RTCOR", "Refresh Timer Constant Counter", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF8000028L, "BSC_RFCNT", "Refresh Count Register", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF800002CL, "BSC_PCTRA", "Port Control Register A", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF8000030L, "BSC_PDTRA", "Port Data Register A", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF8000040L, "BSC_PCTRB", "Port Control Register B", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF8000044L, "BSC_PDTRB", "Port Data Register B", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFF8000048L, "BSC_GPIO", "GPIO Control Register ", LOG);
    }

    /* DYNAMIC MEMORY ALLOCATION SEGMENTS */

    public static final void DMA_SEGMENTS(FlatProgramAPI FPA, MessageLog LOG)
    {
        CREATE_BASE_SEGMENT(FPA, null, "DMA", 0xFFA00000L, 0x44, true, false, LOG);
        CREATE_BITWISE_CONST(FPA, 0xFFA00000L, "DMA_SAR0", "DMA Source Address Register 0", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFFA00004L, "DMA_DAR0", "DMA Destination Address Register 0", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFFA00008L, "DMA_TCR0", "DMA Transfer Count Register 0", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFFA0000CL, "DMA_CHCR0", "DMA Channel Control Register 0", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFFA00010L, "DMA_SAR1", "DMA Source Address Register 1", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFFA00014L, "DMA_DAR1", "DMA Destination Address Register 1", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFFA00018L, "DMA_TCR1", "DMA Transfer Count Register 1", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFFA0001CL, "DMA_CHCR1", "DMA Channel Control Register 1", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFFA00020L, "DMA_SAR2", "DMA Source Address Register 2", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFFA00024L, "DMA_DAR2", "DMA Destination Address Register 2", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFFA00028L, "DMA_TCR2", "DMA Transfer Count Register 2", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFFA0002CL, "DMA_CHRC2", "DMA Channel Control Register 2", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFFA00030L, "DMA_SAR3", "DMA Source Address Register 3", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFFA00032L, "DMA_DAR3", "DMA Destination Address Register 3", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFFA00034L, "DMA_TCR3", "DMA Transfer Count Register 3", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFFA00038L, "DMA_CHCR3", "DMA Channel Control Register 3", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFFA00040L, "DMA_OR", "DMA Operation Register", LOG);
    }

    /* CONTROL SEGMENTS */

    public static final void CPG_SEGMENTS(FlatProgramAPI FPA, MessageLog LOG)
    {
        CREATE_BASE_SEGMENT(FPA, null, "CPG", 0xFFC00000L, 0x14, true, false, LOG);
        CREATE_BITWISE_CONST(FPA, 0xFFC000000L, "CPG_FRCR", "Frequency Control Register", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFFC000004L, "CPG_STBCR", "Standby Control Register", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFFC000008L, "CPG_WCNT", "Watch Timer Counter", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFFC00000CL, "CPG_WCSR", "Watch Timer Status Register", LOG);
        CREATE_BITWISE_CONST(FPA, 0xFFC000010L, "CPG_STBCR2", "Standby Control Register 2", LOG);
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
            FPA.createDWord(ADDRESS_ARG);
        }

        catch (Exception EXEC) 
        {
            LOG.appendException(EXEC);
            return;
        }

        /* AFTER WHICH, WE CREATE THE DESIGNATED PAGE TABLE DESIGNATED FOR THE GIVEN ADDRESS */
        /* THIS IS BY ASSUMING THAT GIVEN THE CURRENT PROGRAM ARGUMENTS, THE PAGE TABLE WILL CREATED */
        /* WHICH WILL BE DESIGNATED BACK TOWARDS THE PROGRAM */

        /* OTHERWISE, NO INPUT WILL BE READ AND NO ARGS WILL BE PASSED */

        try
        {
            FPA.getCurrentProgram().getSymbolTable().createLabel(ADDRESS_ARG, ADDRESS_TYPE, SourceType.IMPORTED);
        }

        catch (InvalidInputException INVALID_EXEC)
        {
            LOG.appendException(INVALID_EXEC);
        }
    }
}
