workspace	"Network Status"
			location("Build")
			configurations { "Debug", "Release" }
			platforms { "Win32" }

project 	"Network Status"
			language "C++"
			targetdir "%{cfg.location}/bin/%{cfg.buildcfg}"

			includedirs{
                        "./include",
                        "./3rdparty/iup/include",
                        "./3rdparty/cd/include",
                        "./3rdparty/im/include",
                        "./3rdparty/sqlite3/",
                        "./3rdparty/cjson/",
					}

			libdirs {
                        "./3rdparty/iup",
                        "./3rdparty/cd",
                        "./3rdparty/im",
                        "./3rdparty/sqlite3/",
					}

			files   {
                        "./src/**.h",
                        "./src/**.c",
                        "./src/**.rc",
                        "./3rdparty/sqlite3/sqlite3.c",
                        "./3rdparty/cjson/cjson.c",
					}

			removefiles {
						"./src/*(1).c",
						}


			links   {
-- System
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
-- IUP
                        "freetype6",
                        "ftgl",
                        "iup",
                        "iupcd",
                        "iupcontrols",
                        "iupfiledlg",
                        "iupgl",
                        "iupglcontrols",
                        "iupim",
                        "iupim",
                        "iupole",
                        "iuptuio",
                        "iupweb",
                        "iup_mglplot",
                        "iup_mglplot_debug",
                        "iup_plot",
                        "iup_scintilla",
                        "iup_scintilla_debug",
                        "zlib1",
-- CD
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
                        "zlib1",
					}



filter "configurations:Debug"
                kind "ConsoleApp"
                defines {
                                "DEBUG",
                                "_WINSOCK_DEPRECATED_NO_WARNINGS",
                                "_CRT_SECURE_NO_WARNING",
                        }
                symbols "On"
                staticruntime "on"
                runtime "Debug"


filter "configurations:Release"
                kind "WindowedApp"
                defines {
                                "NDEBUG",
                                "_WINSOCK_DEPRECATED_NO_WARNINGS",
								"_CRT_SECURE_NO_WARNING",
                                "SQLITE_DQS=0",
                                "SQLITE_THREADSAFE=0",
                                "SQLITE_LIKE_DOESNT_MATCH_BLOBS",
                                "SQLITE_DEFAULT_WAL_SYNCHRONOUS=1",
                                "SQLITE_MAX_EXPR_DEPTH=0",
                                "SQLITE_OMIT_DEPRECATED",
                                "SQLITE_OMIT_SHARED_CACHE",
                        }
                optimize "Full"
                symbols "Off"
                staticruntime "on"
                runtime "Release"
