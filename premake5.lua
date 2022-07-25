workspace "Netstat"
    location("Build")
    configurations { "Debug", "Release" }
    platforms { "Win64", "Win32" }

project "Netstat"
    language "C++"
    targetdir "%{cfg.location}/bin/%{cfg.buildcfg}"

    includedirs {
            "./include", 
            "./3rdparty/iup/include",
            "./3rdparty/cd/include"
            }
            
    libdirs { 
            "./3rdparty/iup",
            "./3rdparty/cd"
            }
    
    files   {
            "./src/**.h",
            "./src/**.c",
            "./src/**.rc"
            }

   -- removefiles { "./Unwanted1.c", "./Unwanted2.c" }

    links   { 
-- System Libs
            "user32", 
            "comdlg32", 
            "kernel32",
            "iphlpapi",
            "ws2_32", 
            "gdi32",           
            "comctl32",
            "uuid", 
            "oleaut32",
            "ole32",           
-- IUP Libs
            "freetype6",
            "ftgl",
            "iup",
            "iupcd",
            "iupcontrols",
            "iupfiledlg",
            "iupgl",
            "iupglcontrols",
            "iupim",
            "iupimglib",
            "iupole",
            "iuptuio",       
            "iupweb",
            "iup_mglplot",
            "iup_mglplot_debug",
            "iup_plot",
            "iup_scintilla",
            "iup_scintilla_debug",
            "zlib1.lib",
-- CD Libs
            "cd",
            "cdcairo",
            "cdcontextplus",
            "cddirect2d",
            "cdgl",
            "cdim",
            "cdpdf",
            "freetype6",
            "ftgl",
            "pdflib",
            "zlib1"
            }


filter "configurations:Debug"
        kind "ConsoleApp"
        defines { "DEBUG",
                "_WINSOCK_DEPRECATED_NO_WARNINGS"
                }
        symbols "On"
        staticruntime "on"
        runtime "Debug"


filter "configurations:Release"
        kind "WindowedApp"
        defines { "NDEBUG",
                "_WINSOCK_DEPRECATED_NO_WARNINGS",
                }
        optimize "Full"
        symbols "Off"
        staticruntime "on"
        runtime "Release"
