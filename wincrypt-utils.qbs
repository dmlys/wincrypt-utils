import qbs
import qbs.Environment

StaticLibrary
{
	condition: qbs.targetOS.contains("windows")
	
	Depends { name: "cpp" }
	Depends { name: "extlib" }
	Depends { name: "dmlys.qbs-common"; required: false }
	Depends { name: "ProjectSettings"; required: false }

	cpp.cxxLanguageVersion : "c++17"
	cpp.includePaths: ["include"]


	Export
	{
		Depends { name: "cpp" }
		Depends { name: "extlib" }

		cpp.cxxLanguageVersion : "c++17"
		cpp.includePaths : [exportingProduct.sourceDirectory + "/include"]
	}

	files: [
		"include/ext/wincrypt/**",
		"src/**",
	]
}
