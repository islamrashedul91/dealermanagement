package com.rashed.pharmacy.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Properties;

import org.apache.tomcat.util.codec.binary.Base64;


public class GetHeader {
	InputStream is = this.getClass().getClassLoader().getResourceAsStream("config.properties");
	Properties prop = new Properties();
	
	//databaseConnnection
	public String getClassForName() throws IOException{
		prop.load(is);
		String class_forName= prop.getProperty("class_forName");
		
		String localDriver = class_forName ;
		//System.out.println("getClassForName -----"+localDriver);
		return localDriver;
	}
	public String getURLLocal() throws IOException{
		prop.load(is);
		String driver_getConnection = prop.getProperty("driver_getConnection");
		
		String localUrl = driver_getConnection;
		//System.out.println("Service URL -----"+localUrl);
		return localUrl;
	}
	public String getDatabaseUserName() throws IOException{
		prop.load(is);
		String userName= prop.getProperty("userName");
		
		String localuserName = userName ;
		//System.out.println("localuserName -----"+localuserName);
		return localuserName;
	}
	public String getDatabasePassword() throws IOException{
		prop.load(is);
		String password= prop.getProperty("password");
		
		String localpassword = password ;
		//System.out.println("getClassForName -----"+localpassword);
		return localpassword;
	}
	//databaseConnnection
	
	public String getRootPath() throws IOException{
		prop.load(is);
		String rootPath= prop.getProperty("rootPath");
		
		String localrootPath = rootPath ;

		return localrootPath;
	}
	
	// for email sending [S]
	public String getHost() throws IOException{
		prop.load(is);
		String host= prop.getProperty("host");
		
		String strHost = host ;

		return strHost;
	}
	
	public String getPort() throws IOException{
		prop.load(is);
		String port= prop.getProperty("port");
		
		String strPort = port ;

		return strPort;
	}
	
	public String getUser() throws IOException{
		prop.load(is);
		String user= prop.getProperty("user");
		
		String strUser = user ;

		return strUser;
	}
	
	public String getPass() throws IOException{
		prop.load(is);
		String pass= prop.getProperty("pass");
		
		String strPass = pass ;

		return strPass;
	}
	// for email sending [E]
	
}
