import sqlite3
import pefile
import string
import hashlib
import inspect
import pydasm
import os
import sys

def eprint(msg):
	print "\t [!]%s" % msg

def convert_char(char):
	if char in string.ascii_letters or char in string.digits or char in string.punctuation or char in string.whitespace:
		return char
	else:
		return r'\x%02x' % ord(char)

def convert_to_printable(s):
	return ''.join([convert_char(c) for c in s])

# c.execute('''CREATE TABLE IF NOT EXISTS NAME
# (
# 	ID INTEGER PRIMARY KEY   AUTOINCREMENT,
# 	peid INTEGER,
# )
# ''')
def CreateDB(c):
	
	c.execute('''CREATE TABLE IF NOT EXISTS peInfo
	(
		ID INTEGER PRIMARY KEY   AUTOINCREMENT,
		pepath text,
		md5 text
	)
	''')
	
	c.execute('''CREATE TABLE IF NOT EXISTS strings
	(
		ID INTEGER PRIMARY KEY   AUTOINCREMENT,
		peid INTEGER,
		string text,
		sin INTEGER
	)
	''')
	
	c.execute('''CREATE TABLE IF NOT EXISTS IMAGE_DOS_HEADER
	(
		ID INTEGER PRIMARY KEY   AUTOINCREMENT,
		peid INTEGER,
		e_magic text,
		e_cblp text,
		e_cp text,
		e_crlc text,
		e_cparhdr text,
		e_minalloc text,
		e_maxalloc text,
		e_ss text,
		e_sp text,
		e_csum text,
		e_ip text,
		e_cs text,
		e_lfarlc text,
		e_ovno text,
		e_res text,
		e_oemid text,
		e_oeminfo text,
		e_res2 text,
		e_lfanew text
	)
	''')
	
	c.execute('''CREATE TABLE IF NOT EXISTS IMAGE_DOS_HEADER_RAW
	(
		ID INTEGER PRIMARY KEY   AUTOINCREMENT,
		peid INTEGER,
		buf text
	)
	''')
	
	c.execute('''CREATE TABLE IF NOT EXISTS IMAGE_NT_HEADERS
	(
		ID INTEGER PRIMARY KEY   AUTOINCREMENT,
		peid INTEGER,
		Signature text
	)
	''')
	
	c.execute('''CREATE TABLE IF NOT EXISTS IMAGE_FILE_HEADER
	(
		ID INTEGER PRIMARY KEY   AUTOINCREMENT,
		peid INTEGER,
		Machine text,
		NumberOfSections text,
		TimeDateStamp text,
		PointerToSymbolTable text,
		NumberOfSymbols text,
		SizeOfOptionalHeader text,
		Characteristics text
	)
	''')
	
	c.execute('''CREATE TABLE IF NOT EXISTS IMAGE_OPTIONAL_HEADER
	(
		ID INTEGER PRIMARY KEY   AUTOINCREMENT,
		peid INTEGER,
		type INTEGER,
		Magic text,
		MajorLinkerVersion text,
		MinorLinkerVersion text,
		SizeOfCode text,
		SizeOfInitializedData text,
		SizeOfUninitializedData text,
		AddressOfEntryPoint text,
		BaseOfCode text,
		BaseOfData text,
		ImageBase text,
		SectionAlignment text,
		FileAlignment text,
		MajorOperatingSystemVersion text,
		MinorOperatingSystemVersion text,
		MajorImageVersion text,
		MinorImageVersion text,
		MajorSubsystemVersion text,
		MinorSubsystemVersion text,
		Reserved1 text,
		SizeOfImage text,
		SizeOfHeaders text,
		CheckSum text,
		Subsystem text,
		DllCharacteristics text,
		SizeOfStackReserve text,
		SizeOfStackCommit text,
		SizeOfHeapReserve text,
		SizeOfHeapCommit text,
		LoaderFlags text,
		NumberOfRvaAndSizes text
	)
	''')
	
	c.execute('''CREATE TABLE IF NOT EXISTS IMAGE_SECTION_HEADER
	(
		ID INTEGER PRIMARY KEY   AUTOINCREMENT,
		peid INTEGER,
		Name text,
		Misc text,
		Misc_PhysicalAddress text,
		Misc_VirtualSize text,
		VirtualAddress text,
		SizeOfRawData text,
		PointerToRawData text,
		PointerToRelocations text,
		PointerToLinenumbers text,
		NumberOfRelocations text,
		NumberOfLinenumbers text,
		Characteristics text,
		Entropy text,
		MD5 text
	)
	''')
	
	c.execute('''CREATE TABLE IF NOT EXISTS IMAGE_DIRECTORY
	(
		ID INTEGER PRIMARY KEY   AUTOINCREMENT,
		peid INTEGER,
		name text,
		VirtualAddress text,
		Size text
	)
	''')
	
	c.execute('''CREATE TABLE IF NOT EXISTS DIRECTORY_ENTRY_IMPORT
	(
		ID INTEGER PRIMARY KEY   AUTOINCREMENT,
		peid INTEGER,
		dll text,
		func text,
		addr text
	)
	''')
	
	c.execute('''CREATE TABLE IF NOT EXISTS DIRECTORY_ENTRY_IMPORT_HASH
	(
		ID INTEGER PRIMARY KEY   AUTOINCREMENT,
		peid INTEGER,
		hash text
	)
	''')
	
	c.execute('''CREATE TABLE IF NOT EXISTS DIRECTORY_ENTRY_EXPORT
	(
		ID INTEGER PRIMARY KEY   AUTOINCREMENT,
		peid INTEGER,
		name text,
		addr text
	)
	''')
	
	c.execute('''CREATE TABLE IF NOT EXISTS resource_strings
	(
		ID INTEGER PRIMARY KEY   AUTOINCREMENT,
		peid INTEGER,
		string text
	)
	''')
	
	c.execute('''CREATE TABLE IF NOT EXISTS FileInfo
	(
		ID INTEGER PRIMARY KEY   AUTOINCREMENT,
		peid INTEGER,
		name text,
		value text
	)
	''')
	
	c.execute('''CREATE TABLE IF NOT EXISTS EP_DIS
	(
		ID INTEGER PRIMARY KEY   AUTOINCREMENT,
		peid INTEGER,
		dis text,
		hash text
	)
	''')

def InitBinary(c, path, md5):
	c.execute("Insert into peInfo (pepath, md5) VALUES (?,?);", (path,md5))
	c.execute("SELECT last_insert_rowid();")
	val = c.fetchone()[0]
	return val;

def strings(peid, c, filename, min=4):
	
	resVal = ()
	resList = []
	i=0
	with open(filename, "rb") as f:
		result = ""
		for ch in f.read():
			i = i+1
			if ch in string.printable:
				result += ch
				continue
			if len(result) >= min:
				resVal = (peid,result,i-len(result))
				resList.append(resVal)
			result = ""
	
	c.executemany("INSERT INTO strings (peid,string,sin) VALUES (?,?,?);", resList )
	
	return resList

def matchBytes():
	return 0

def ParsePE(c, peid, file):
	
	pe = pefile.PE(file)
	
	try:
		c.execute("INSERT into IMAGE_DOS_HEADER (peid,e_magic,e_cblp,e_cp,e_crlc,e_cparhdr,e_minalloc,e_maxalloc,e_ss,e_sp,e_csum,e_ip,e_cs,e_lfarlc,e_ovno,e_res,e_oemid,e_oeminfo,e_res2,e_lfanew) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
			(
			peid,
			"0x%04x"%pe.DOS_HEADER.e_magic,
			"0x%04x"%pe.DOS_HEADER.e_cblp,
			"0x%04x"%pe.DOS_HEADER.e_cp,
			"0x%04x"%pe.DOS_HEADER.e_crlc,
			"0x%04x"%pe.DOS_HEADER.e_cparhdr,
			"0x%04x"%pe.DOS_HEADER.e_minalloc,
			"0x%04x"%pe.DOS_HEADER.e_maxalloc,
			"0x%04x"%pe.DOS_HEADER.e_ss,
			"0x%04x"%pe.DOS_HEADER.e_sp,
			"0x%04x"%pe.DOS_HEADER.e_csum,
			"0x%04x"%pe.DOS_HEADER.e_ip,
			"0x%04x"%pe.DOS_HEADER.e_cs,
			"0x%04x"%pe.DOS_HEADER.e_lfarlc,
			"0x%04x"%pe.DOS_HEADER.e_ovno,
			pe.DOS_HEADER.e_res,
			"0x%04x"%pe.DOS_HEADER.e_oemid,
			"0x%04x"%pe.DOS_HEADER.e_oeminfo,
			pe.DOS_HEADER.e_res2,
			"0x%08x"%pe.DOS_HEADER.e_lfanew,
			)
		)
	except:
		eprint("FAILED IMAGE_DOS_HEADER")
	
	try:
		c.execute("INSERT INTO IMAGE_NT_HEADERS (peid,Signature) VALUES (?,?)", (peid,"0x%08x"%pe.NT_HEADERS.Signature,))
	except:
		eprint("Failed IMAGE_NT_HEADERS")
	
	try:
		c.execute('INSERT INTO IMAGE_FILE_HEADER (peid,Machine,NumberOfSections,TimeDateStamp,PointerToSymbolTable,NumberOfSymbols,SizeOfOptionalHeader,Characteristics) VALUES (?,?,?,?,?,?,?,?)',
			(
			peid,
			"0x%04x"%pe.FILE_HEADER.Machine,
			"0x%04x"%pe.FILE_HEADER.NumberOfSections,
			"0x%08x"%pe.FILE_HEADER.TimeDateStamp,
			"0x%08x"%pe.FILE_HEADER.PointerToSymbolTable,
			"0x%08x"%pe.FILE_HEADER.NumberOfSymbols,
			"0x%04x"%pe.FILE_HEADER.SizeOfOptionalHeader,
			"0x%04x"%pe.FILE_HEADER.Characteristics
			)
		)
	except:
		eprint( "Failed IMAGE_FILE_HEADER")
	
	try:
		if pe.OPTIONAL_HEADER.name is "IMAGE_OPTIONAL_HEADER64":
			c.execute('INSERT INTO IMAGE_OPTIONAL_HEADER (peid,type,Magic,MajorLinkerVersion,MinorLinkerVersion,SizeOfCode,SizeOfInitializedData,SizeOfUninitializedData,AddressOfEntryPoint,BaseOfCode,BaseOfData,ImageBase,SectionAlignment,FileAlignment,MajorOperatingSystemVersion,MinorOperatingSystemVersion,MajorImageVersion,MinorImageVersion,MajorSubsystemVersion,MinorSubsystemVersion,Reserved1,SizeOfImage,SizeOfHeaders,CheckSum,Subsystem,DllCharacteristics,SizeOfStackReserve,SizeOfStackCommit,SizeOfHeapReserve,SizeOfHeapCommit,LoaderFlags,NumberOfRvaAndSizes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
				(
				peid,
				64,
				"0x%04x"%pe.OPTIONAL_HEADER.Magic,
				"0x%02x"%pe.OPTIONAL_HEADER.MajorLinkerVersion,
				"0x%02x"%pe.OPTIONAL_HEADER.MinorLinkerVersion,
				"0x%08x"%pe.OPTIONAL_HEADER.SizeOfCode,
				"0x%08x"%pe.OPTIONAL_HEADER.SizeOfInitializedData,
				"0x%08x"%pe.OPTIONAL_HEADER.SizeOfUninitializedData,
				"0x%08x"%pe.OPTIONAL_HEADER.AddressOfEntryPoint,
				"0x%08x"%pe.OPTIONAL_HEADER.BaseOfCode,
				'',
				"0x%08x"%pe.OPTIONAL_HEADER.ImageBase,
				"0x%08x"%pe.OPTIONAL_HEADER.SectionAlignment,
				"0x%08x"%pe.OPTIONAL_HEADER.FileAlignment,
				"0x%04x"%pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
				"0x%04x"%pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
				"0x%04x"%pe.OPTIONAL_HEADER.MajorImageVersion,
				"0x%04x"%pe.OPTIONAL_HEADER.MinorImageVersion,
				"0x%04x"%pe.OPTIONAL_HEADER.MajorSubsystemVersion,
				"0x%04x"%pe.OPTIONAL_HEADER.MinorSubsystemVersion,
				"0x%08x"%pe.OPTIONAL_HEADER.Reserved1,
				"0x%08x"%pe.OPTIONAL_HEADER.SizeOfImage,
				"0x%08x"%pe.OPTIONAL_HEADER.SizeOfHeaders,
				"0x%08x"%pe.OPTIONAL_HEADER.CheckSum,
				"0x%04x"%pe.OPTIONAL_HEADER.Subsystem,
				"0x%04x"%pe.OPTIONAL_HEADER.DllCharacteristics,
				"0x%08x"%pe.OPTIONAL_HEADER.SizeOfStackReserve,
				"0x%08x"%pe.OPTIONAL_HEADER.SizeOfStackCommit,
				"0x%08x"%pe.OPTIONAL_HEADER.SizeOfHeapReserve,
				"0x%08x"%pe.OPTIONAL_HEADER.SizeOfHeapCommit,
				"0x%08x"%pe.OPTIONAL_HEADER.LoaderFlags,
				"0x%08x"%pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
				)
			)
		else:
			c.execute('INSERT INTO IMAGE_OPTIONAL_HEADER (peid,type,Magic,MajorLinkerVersion,MinorLinkerVersion,SizeOfCode,SizeOfInitializedData,SizeOfUninitializedData,AddressOfEntryPoint,BaseOfCode,BaseOfData,ImageBase,SectionAlignment,FileAlignment,MajorOperatingSystemVersion,MinorOperatingSystemVersion,MajorImageVersion,MinorImageVersion,MajorSubsystemVersion,MinorSubsystemVersion,Reserved1,SizeOfImage,SizeOfHeaders,CheckSum,Subsystem,DllCharacteristics,SizeOfStackReserve,SizeOfStackCommit,SizeOfHeapReserve,SizeOfHeapCommit,LoaderFlags,NumberOfRvaAndSizes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
				(
				peid,
				32,
				"0x%04x"%pe.OPTIONAL_HEADER.Magic,
				"0x%02x"%pe.OPTIONAL_HEADER.MajorLinkerVersion,
				"0x%02x"%pe.OPTIONAL_HEADER.MinorLinkerVersion,
				"0x%08x"%pe.OPTIONAL_HEADER.SizeOfCode,
				"0x%08x"%pe.OPTIONAL_HEADER.SizeOfInitializedData,
				"0x%08x"%pe.OPTIONAL_HEADER.SizeOfUninitializedData,
				"0x%08x"%pe.OPTIONAL_HEADER.AddressOfEntryPoint,
				"0x%08x"%pe.OPTIONAL_HEADER.BaseOfCode,
				"0x%08x"%pe.OPTIONAL_HEADER.BaseOfData,
				"0x%16x"%pe.OPTIONAL_HEADER.ImageBase,
				"0x%08x"%pe.OPTIONAL_HEADER.SectionAlignment,
				"0x%08x"%pe.OPTIONAL_HEADER.FileAlignment,
				"0x%04x"%pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
				"0x%04x"%pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
				"0x%04x"%pe.OPTIONAL_HEADER.MajorImageVersion,
				"0x%04x"%pe.OPTIONAL_HEADER.MinorImageVersion,
				"0x%04x"%pe.OPTIONAL_HEADER.MajorSubsystemVersion,
				"0x%04x"%pe.OPTIONAL_HEADER.MinorSubsystemVersion,
				"0x%08x"%pe.OPTIONAL_HEADER.Reserved1,
				"0x%08x"%pe.OPTIONAL_HEADER.SizeOfImage,
				"0x%08x"%pe.OPTIONAL_HEADER.SizeOfHeaders,
				"0x%08x"%pe.OPTIONAL_HEADER.CheckSum,
				"0x%04x"%pe.OPTIONAL_HEADER.Subsystem,
				"0x%04x"%pe.OPTIONAL_HEADER.DllCharacteristics,
				"0x%16x"%pe.OPTIONAL_HEADER.SizeOfStackReserve,
				"0x%16x"%pe.OPTIONAL_HEADER.SizeOfStackCommit,
				"0x%16x"%pe.OPTIONAL_HEADER.SizeOfHeapReserve,
				"0x%16x"%pe.OPTIONAL_HEADER.SizeOfHeapCommit,
				"0x%08x"%pe.OPTIONAL_HEADER.LoaderFlags,
				"0x%08x"%pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
				)
			)
	except:
		eprint( "Failed IMAGE_OPTIONAL_HEADER")
	
	try:
		for section in pe.sections:
			entropy = section.get_entropy()
			md5 = section.get_hash_md5()
			c.execute('INSERT INTO IMAGE_SECTION_HEADER (peid,Name,Misc,Misc_PhysicalAddress,Misc_VirtualSize,VirtualAddress,SizeOfRawData,PointerToRawData,PointerToRelocations,PointerToLinenumbers,NumberOfRelocations,NumberOfLinenumbers,Characteristics,Entropy,MD5) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
				(
				peid,
				section.Name,
				"0x%08x"%section.Misc,
				"0x%08x"%section.Misc_PhysicalAddress,
				"0x%08x"%section.Misc_VirtualSize,
				"0x%08x"%section.VirtualAddress,
				"0x%08x"%section.SizeOfRawData,
				"0x%08x"%section.PointerToRawData,
				"0x%08x"%section.PointerToRelocations,
				"0x%08x"%section.PointerToLinenumbers,
				"0x%04x"%section.NumberOfRelocations,
				"0x%04x"%section.NumberOfLinenumbers,
				"0x%08x"%section.Characteristics,
				entropy,
				md5
				)
			)
	except:
		eprint( "Failed IMAGE_SECTION_HEADER")
	
	try:
		for data_dir in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
			c.execute('INSERT INTO IMAGE_DIRECTORY (peid,name,VirtualAddress,Size) VALUES (?,?,?,?)',
				(
					peid,
					data_dir.name,
					"0x%08x"%data_dir.VirtualAddress,
					data_dir.Size
				)
			)
	except:
		eprint( "Failed IMAGE_DIRECTORY")
	
	try:
		for entry in pe.DIRECTORY_ENTRY_IMPORT:
			dll_name = entry.dll
			for func in entry.imports:
				c.execute('INSERT INTO DIRECTORY_ENTRY_IMPORT (peid,dll,func,addr) VALUES (?,?,?,?)',
					(
						peid,
						dll_name,
						func.name,
						"0x%16x"%func.address
					)
				)
	except:
		eprint( "Failed DIRECTORY_ENTRY_IMPORT")
	
	try:
		c.execute('INSERT INTO DIRECTORY_ENTRY_IMPORT_HASH (peid,hash) VALUES (?,?)',
			(
				peid,
				pe.get_imphash().encode('hex')
			)
		)
	except:
		eprint( "Failed DIRECTORY_ENTRY_IMPORT_HASH")
	
	try:
		c.execute('INSERT INTO IMAGE_DOS_HEADER_RAW (peid,buf) VALUES (?,?)',
			(
				peid,
				pe.header.encode('hex')
			)
		)
	except:
		eprint( "Failed IMAGE_DOS_HEADER_RAW")
	
	try:
		if hasattr(pe, 'OPTIONAL_HEADER'):
			if pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size != 0:
				for func in pe.DIRECTORY_ENTRY_EXPORT.symbols:
					c.execute('INSERT INTO DIRECTORY_ENTRY_EXPORT (peid,name,addr) VALUES (?,?,?)',
						(
							peid,
							func.name,
							"0x%08x"% func.address
						)
					)
	except:
		eprint( "Failed OPTIONAL_HEADER.DATA_DIRECTORY")
	
	try:
		for st in pe.get_resources_strings():
			try:
				c.execute("INSERT INTO resource_strings (peid,string) VALUES (?,?)",(peid,st))
			except:
				continue
	except:
		eprint( "Failed resource_strings")
	
	try:
		if hasattr(pe, 'FileInfo'):
			for entry in pe.FileInfo:
				if hasattr(entry, 'StringTable'):
					for st_entry in entry.StringTable:
						c.execute("INSERT INTO FileInfo (peid,name,value) VALUES (?,?,?)",(peid,"LangID", st_entry.LangID))
						for str_entry in st_entry.entries.items():
							c.execute("INSERT INTO FileInfo (peid,name,value) VALUES (?,?,?)",(peid, convert_to_printable(str_entry[0]), convert_to_printable(str_entry[1])))
							
		if pe.is_exe():
			c.execute("INSERT INTO FileInfo (peid,name,value) VALUES (?,?,?)",(peid, "FileType", "EXE"))
		elif pe.is_dll():
			c.execute("INSERT INTO FileInfo (peid,name,value) VALUES (?,?,?)",(peid, "FileType", "DLL"))
		elif pe.is_driver():
			c.execute("INSERT INTO FileInfo (peid,name,value) VALUES (?,?,?)",(peid, "FileType", "DRIVER"))
		else:
			c.execute("INSERT INTO FileInfo (peid,name,value) VALUES (?,?,?)",(peid, "FileType", "UNKNOWN"))
	except:
		eprint( "Failed FileInfo")
	
	try:
		ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
		ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
		mmd = pe.get_memory_mapped_image()[ep:ep+100]
		mmd_len = len(mmd)
		ofs = 0
		disassembly = ''
		try:
			while ofs < mmd_len:
				i = pydasm.get_instruction(mmd[ofs:], pydasm.MODE_32)
				disassembly += pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+ofs) + '\n'
				ofs = ofs + i.length
		except:
			eprint( "Problem completeing EP disassmebly")
		
		m = hashlib.md5()
		m.update(mmd)
		ep_hash = m.digest().encode('hex')
		
		c.execute("INSERT INTO EP_DIS (peid,dis,hash) VALUES (?,?,?)",(peid,disassembly,ep_hash))
	except:
		eprint( "Failed EP Disassembly")
	
	
	# for rd in pe.DIRECTORY_ENTRY_RESOURCE.entries:
		# print rd.name
	
	# print pe.generate_checksum()
	
			

	pe.close()
	
	return 0


###      ###
### MAIN ###
###      ###

sqldb = 'test.db' #database name
walk_dir = "C:\\test\\" # directory of files

for root, subdirs, files in os.walk(walk_dir):
	for file in files:
		fn = root+"\\"+file
		print fn
		
		conn = sqlite3.connect(sqldb)
		c = conn.cursor()
		
		md5 = hashlib.md5(open(fn, 'rb').read()).hexdigest()
		CreateDB(c)
		peid = InitBinary(c, fn, md5)
		pe = ParsePE(c, peid, fn)
		stringList = strings(peid,c, fn)
		
		conn.commit()
		conn.close()

print "END"