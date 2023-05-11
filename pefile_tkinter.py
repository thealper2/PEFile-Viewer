import tkinter as tk
import tkinter.filedialog as filedialog
import pefile

def browse_file():
    filename = filedialog.askopenfilename(filetypes=[("Executable Files", "*.exe")])
    if filename:
        pe = pefile.PE(filename)
        show_file_info(pe)

        
def show_file_info(pe):
    try:
        try:
            assert pe.DOS_HEADER.e_magic == 0x5A4D
            assert pe.NT_HEADERS.Signature == 0x4550

        except:
            info = f"Invalid file.\n"
            return

        # INFOS #
        info = f"[*] Infos\n"
        info += f"Image base: %s\n" % format(hex(pe.OPTIONAL_HEADER.ImageBase))
        info += f"Entry point: %s\n" % format(hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
        info += f"Number of sections: %s\n" + format(pe.FILE_HEADER.NumberOfSections)
        info += f"Timestamp: %s\n" % format(pe.FILE_HEADER.TimeDateStamp)
        info += f"Machine type: %s\n" % format(pe.FILE_HEADER.Machine)
        info += f"\n"
        
        # SECTIONS #
        info += f"[*] Sections\n"
        for section in pe.sections:
            info += f"".format(section.Name.decode('utf-8'))
            info += f'\tVirtual Address: %s\n' % format(hex(section.VirtualAddress))
            info += f'\tVirtual Size: %s\n' % format(hex(section.Misc_VirtualSize))
            info += f'\tRaw Size: %s\n' % format(hex(section.SizeOfRawData))
        
        info += f"\n"
        
        # IMPORTS #
        info += f"[*] Imports\n"
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            info += f"\t No imports.\n"
            
        else:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                info += f"\t%s\n" % format(entry.dll.decode("utf-8"))
                if entry.imports:
                    for function in entry.imports:
                        if function.name:
                            info += f"\t\t%s\n" % format(function.name.decode("utf-8"))
                            
                        else:
                            info += f"\t\t Unknown function.\n"
                            
        info += f"\n"
        
        # EXPORTS #
        info += f"[*] Exports\n"
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            info += f"\t No exports.\n"
            
        else:
            for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                info += f"\t%s\n" % format(export.name.decode("utf-8"))
                            
    except pefile.PEFormatError:
        info += f"Invalid PE File.\n"
       
    info += "\n"
    text.delete(1.0, tk.END)
    text.insert(tk.END, info)

root = tk.Tk()
root.title("PE File Info")
root.geometry("400x300")

browse_button = tk.Button(root, text="Browse", command=browse_file)
browse_button.pack(pady=10)

text = tk.Text(root)
text.pack(expand=True, fill=tk.BOTH)

root.mainloop()
