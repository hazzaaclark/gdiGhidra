/* Copyright (C) Harry Clark */

/* SEGA Dreamcast GCI Tool for GHIDRA */

/* THIS FILE PERTAINS TO THE FUNCTIONALITY AND OR DECLARATION OF */
/* THE HITACHI S4'S VECTOR TABLE */

/*  SEE SECTION 5.4: https://mc.pp.se/dc/files/h14th002d2.pdf#page=102 */

package main.dc;

import java.io.IOException;
import java.sql.Struct;
import java.util.*;

public class Vectors
{
    static int VECTOR_SIZE = 0x100;
    static int VECTOR_COUNT = VECTOR_SIZE / 4;
     
}
