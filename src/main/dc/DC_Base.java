/* COPYRIGHT (C) HARRY CLARK 2024 */

/* SEGA DREAMCAST GDI TOOL FOR GHIDRA */

/* THIS FILE PERTAINS TOWARDS THE BASE FUNCTIONALITY OF THE PROGRAM */

package gdi;

/* JAVA INCLUDES */

import java.awt.Component;
import java.util.List;
import java.util.jar.Attributes.Name;

import ghidra.app.util.Option;

public class DC_Base extends Option
{
    private static String SELECTED_OPTION;
    private final static String[] OPTION_ADDRESS = new String[]
    {
        "0x8C000000",
        "0x0C000000", 
    };

    /* USES SUPER BY EXTENSION OF THE EXTEND KEYWORD */
    /* TO ENVOKE THE SAME METHODS */

    public DC_Base(String FILE_NAME, Object VALUE, Class<?> valueClass, String args)
    {
        super(FILE_NAME, valueClass, VALUE, args, null);
    }

    public Option COPY_OPTION()
    {
        return new DC_Base(SELECTED_OPTION, OPTION_ADDRESS, getValueClass(), SELECTED_OPTION);
    }
}
