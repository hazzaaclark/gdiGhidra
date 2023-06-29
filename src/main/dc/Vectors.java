/* Copyright (C) Harry Clark */

/* SEGA Dreamcast GCI Tool for GHIDRA */

/* THIS FILE PERTAINS TO THE FUNCTIONALITY AND OR DECLARATION OF */
/* THE HITACHI S4'S VECTOR TABLE */

/*  SEE SECTION 5.4: https://mc.pp.se/dc/files/h14th002d2.pdf#page=102 */
/* https://retrocdn.net/images/6/61/SH-4_32-bit_CPU_Core_Architecture.pdf */

package main.dc;

import java.io.IOException;
import main.Interfaces.*;

public class Vectors
{
    /* CREATE PUBLIC UTILITY AKIN TO C'S MACROS */
    /* THIS ALLOWS GHIDRA TO DETERMINE THE HEX VALUES */
    /* IN ORDER TO DETERMINE THE ADDRESS' ON THE VECTOR TABLE */

    public static int VECTOR_SIZE = 0x100;
    public static int VECTOR_COUNT = VECTOR_SIZE / 4;
    public static int OFFSET = 0x000;

    public static String[] VECTOR_TYPES =
    {
        "POWER_ON", "MANUAL_RESET", "UDI_RESET", "INSTR_TLB_EXC",
        "DATA_TLB_EXC", "BREAK_BEFORE_INSTR_EXC", "INSTR,ADDR,ERR",
        "INSTR,TLB_MISS,EXC", "INSTR,TLB_PROT,EXC", "ILLEGAL_INSTR_EXC",
        "ILLEGAL_SLOT", "FPU_DISABLE", "DATA_ADDR_READ", "DATA_ADDR_WRITE",
        "DATA_TLB_READ", "DATA_TLB_WRITE", "DATA_TLB_PRO_READ", "DATA_TLB_PRO_WRITE",
        "FPU_EXC", "PAGE_WRITE_EXC", "TRAPA", "USER_BREAK", "NO_MASK_IRQ", "MODULE_IRQ" 
    };

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
