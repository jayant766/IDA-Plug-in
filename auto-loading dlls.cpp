#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <strlist.hpp>

#define MAXLIBS 5

int IDAP_init (void)
{
    if (inf.filetype != f_PE) {
        warning("Only PE executable file format supported. \n");
        return PLUGIN_SKIP;
    }

    return PLUGIN_KEEP;
}

void IDAP_term(void)
{
    return;
}

void IDAP_run(int arg)
{
    char loadLibs [MAXLIBS] [MAXSTR];
    int libno = 0, i, strcount = get_strlist_qty ();

    if (strcount == 0)
    {
        msg("No strings found in this binary or IDA hasn't finished processing the binary yet.");
        return;
    }

    msg("%d strings found, checkng for DLL use..", srcount);

    //Loop through all strings to find any string that contains
    //.dll. This will eventuall be our list of the DLLs to load.

    for (i = 0; i < strcount; i++)
    {
        char string [MAXSTR];
        string_info_t si;
        //Get the string item
        get_strlist_item(i, &si);

        if (si.length < sizeof (string))
        {
            //Retrieve the string from the binary
            ge_many_bytes(si.ea, string, si.lenght);

            //We are only interested in C strings.
            if (si.type == 0)
            {
                //.. and if the string contains .dll
                if (stristr(string, ".dll") && libno < MAXKIBS)
                {
                    //and the string to the list of the DLLs to load later on.
                    qstencpy (loadlibs[libnno++], string, MAXSTR-1);
                }

            }
        }
    }
    if (libno == 0)
    {
        msg("No Dll files found in the strings.");
        return;
    }
    //Now go through the list of the libraries found and load them.
    msg("loading the first %d libraries found...\n", MAXLIBS);

    for (i=0; i < libno; i++)
    {
        msg("Lib: %s\n", LoadLibs[i]);

        //ask the user for the full path to DLL (the executable will only have the file name)
        char *file = askfile_cv(0, loadLibs[i], "File path...\n", NULL);

        //Load the DLL using the pa loader module
        if (load_loader_module(NULL, "pe", file, 0))
        {
            msg("Successfully loaded %s\n", loadLibs[i]);
        }
        else{
            msg("Failed to load %s\n", loadLibs[i]);
        }
        
    }

    char IDAP_comment[] = "DLL Auto-Loader";
    char IDAP_help[] = "Loads the first 5 DLLs mentioned in a binary file\n";

    char IDAP_name[] = "DLL Auto-Loader";
    char IDAP_hotkey[] = "Alt-D";

    plugin_t PLUGIN =
    {
        IDP_INTERFACE_VERSION,
        0,
        IDAP_init,
        IDAP_term,
        IDAP_run,
        IDAP_comment,
        IDAP_help,
        IDAP_name,
        IDAP_hotkey
    } ;

}
