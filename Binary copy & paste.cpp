#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>

#define MAX_COPYPASTE 1024

// This will hold our copied buffer for pasting
char data[MAX_COPYPASTE];

// Bytes copied into the above buffer
ssize_t filled = 0;

// Insert the following two lines into your plugins.cfg file
// Replace pluginname with the filename of your plugin minus the extension.
// Copy_Buffer pluginname Alt-C 0
// Paste_Buffer pluginname Alt-V 1

int IDAP_init(void)
{
 return PLUGIN_KEEP;
}

void IDAP_term(void)
{
 return;
}

void copy_buffer() {
 ea_t saddr, eaddr;
 ssize_t size;

 // Get the boundaries of the user selection
 if (read_selection(&saddr, &eaddr)){
     // Work out the size, make sure it doesn't exceed the buffer
    // we have allocated.
    size = eaddr - saddr;
    if (size > MAX_COPYPASTE) 
    {
        warning("You can only copy a max of %d bytes\n", MAX_COPYPASTE);
        return;
    }
    
 // Get the bytes from the file, store it in our buffer
 if (get_many_bytes(saddr, data, size)) {
 filled = size;
 msg("Successfully copied %d bytes from %a into memory.\n",
size,
saddr);
 } else {
 filled = 0;
 }
 } else {
 warning("No bytes selected!\n");
 return;
 }
}
void paste_buffer() {
 // Get the cursor position. This is where we will paste to
 ea_t curpos = get_screen_ea();
 // Make sure the buffer has been filled with a Copy operation first.
 if (filled) {
 // Patch the binary (paste)
 patch_many_bytes(curpos, data, filled);
 msg("Patched %d bytes at %a.\n", filled, curpos);
 } else {
 warning("No data to paste!\n");
 return;
 }
}
void IDAP_run(int arg) {
 // Based on the argument supplied in plugins.cfg,
 // we can use the one plug-in for both the copy
 // and paste operations.
 switch(arg) {
 case 0:
 copy_buffer();
 break;
 case 1:
 paste_buffer();
 break;
 default:
 warning("Invalid usage!\n");
 return;
 }
}
// These are actually pointless because we'll be overriding them
// in plugins.cfg
char IDAP_comment[] = "Binary Copy and Paster";
char IDAP_help[] = "Allows the user to copy and paste binary\n";
char IDAP_name[] = "Binary Copy and Paster";
char IDAP_hotkey[] = "Alt-I";
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
};