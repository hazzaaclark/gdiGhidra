/* Copyright (C) Harry Clark */

/* SEGA Dreamcast GDI Tool for GHIDRA */

/* THIS FILE PERTAINS TO THE FUNCTIONALITY AND OR DECLARATION OF */
/* THE HITACHI S4'S VECTOR TABLE */

/*  SEE SECTION 5.4: https://mc.pp.se/dc/files/h14th002d2.pdf#page=102 */
/* https://retrocdn.net/images/6/61/SH-4_32-bit_CPU_Core_Architecture.pdf */

package main.dc;

/* NESTED INCLUDES */

import java.io.IOException;

/* GHIDRA INCLUDES */

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.StructureDataType;
import main.dc.Interfaces.*;
import ghidra.program.model.data.DataType;
import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;

public class Vectors
{
    /* CREATE PUBLIC UTILITY AKIN TO C'S MACROS */
    /* THIS ALLOWS GHIDRA TO DETERMINE THE HEX VALUES */
    /* IN ORDER TO DETERMINE THE ADDRESS' ON THE VECTOR TABLE */

    public static int VECTOR_SIZE = 0x100;
    public static int VECTOR_COUNT = VECTOR_SIZE / 4;
    public static int OFFSET = 0x000;

    private VECTOR_FUNC[] VECTORS;

    public static String[] VECTOR_TYPES =
    {
        "POWER_ON", "MANUAL_RESET", "UDI_RESET", "INSTR_TLB_EXC",
        "DATA_TLB_EXC", "BREAK_BEFORE_INSTR_EXC", "INSTR,ADDR,ERR",
        "INSTR,TLB_MISS,EXC", "INSTR,TLB_PROT,EXC", "ILLEGAL_INSTR_EXC",
        "ILLEGAL_SLOT", "FPU_DISABLE", "DATA_ADDR_READ", "DATA_ADDR_WRITE",
        "DATA_TLB_READ", "DATA_TLB_WRITE", "DATA_TLB_PRO_READ", "DATA_TLB_PRO_WRITE",
        "FPU_EXC", "PAGE_WRITE_EXC", "TRAPA", "USER_BREAK", "NO_MASK_IRQ", "MODULE_IRQ" 
    };

    /* ALLOCATE A DATA STRUCTURE RELATIVE TO THE NAMES ESTABLISHED IN THE STRING ARRAY */
    /* THIS IS USING A GHIDRA PRE-DIRECTIVE */

    public DataType ALLOC_VECTOR_TYPE(StructureDataType VECTOR_STRUCTURE)
    {
        VECTOR_STRUCTURE = new StructureDataType("VECTOR_TYPES", 0);

        for (int i = 0; i < VECTOR_COUNT; i++)
        {
            VECTOR_STRUCTURE.add(VECTOR_STRUCTURE, VECTOR_COUNT, null, null);
        }

        return VECTOR_STRUCTURE;
    }

    /* CREATES A PUBLIC CONSTRUCTOR FOR THE LENGTH OF THE VECTOR TABLE */
    /* SUCH THAT WHEN IT IS LESS AND EQUAL TO THE OFFSET SIZE OF THE VECTOR */
    /* IT WILL ALLOCATE MEMORY ACCORDINGLY */

    public Vectors(FlatDecompilerAPI API, BinaryReader BIN) throws IOException
    {
        if(BIN.length() <= VECTOR_SIZE) return;

        BIN.setPointerIndex(0);     // SET ORIGIN TO 0
        BIN.setLittleEndian(false); // LITTLE ENDIAN IS HERE FOR HEX READINGS
    }

    /* RETURN THE TYPE OF VECTOR FROM THE STRING ARRAY */
    /* BASED ON THE LENGTH OF THE STRING ARRAY */

    /* THIS IS DETERMIEND BY THE NUMERICAL INCREASE IN AN ARBRITARY INT VALUE */

    public VECTOR_FUNC GET_VECTOR_INDEX(int INDEX)
    {
        if(INDEX >= 0 && INDEX < VECTOR_TYPES.length) return VECTORS[INDEX];
        return null;
    }

    /* RETURN THE FUNCTION METHODS BASED ON THE FUNCTION */
    /* NAME AND ADDRESS */

    public static class FUNCTION
    {
        public static I_ADDRESS ADDRESS;
        public static I_NAME NAME;

        public I_ADDRESS GET_ADDR()
        {
            return FUNCTION.ADDRESS;
        }

        public I_NAME GET_FUNC_NAME()
        {
            return FUNCTION.NAME;
        }
    } 
     
}
