package com.cipher.util;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintWriter;

public class FileUtil {
	public boolean saveObject(String filepath, Object obj) {
		boolean bRet = false;
		PrintWriter pw = null;
		try {
			pw = new PrintWriter(new FileOutputStream(filepath));
			pw.print(obj);
			bRet = true;
		} catch (FileNotFoundException fnfe) {
			fnfe.printStackTrace();
		} finally {
			if (pw != null) {
				pw.close();
				pw = null;
			}
		}
		return bRet;
	}
}
