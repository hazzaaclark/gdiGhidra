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

public class DC_Loader
{
    /* SEEK VALUES FOR VECTOR TABLE HEADER CHECKSUM */

    public static int SEEK_SET = 0;
    public static int SEEK_CUR = 1;
    public static int SEEK_END = 2;

    /* DE FACTO STANDARD HEX VALUES FOR CD-ROMS  */

    public static long DC_BASE = 0x20000000;
    public static long DC_INIT = 0x80000000;

    /* DEFINE THE CONSTANT BYTE OF THE INTERRUPT MASK IRQ */
    /* THIS WORKS BY TAKING INTO ACCOUNT THE LOWER BYTES ON THE CPU */
    /* WHICH PARSES INFORMATION BACK AND FORTH FROM THE GD DRIVE */

    /* SECTION TABLE 5 - PAGE 32: https://retrocdn.net/images/6/61/SH-4_32-bit_CPU_Core_Architecture.pdf#page=32 */

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
}
