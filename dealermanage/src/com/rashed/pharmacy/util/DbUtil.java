package com.rashed.pharmacy.util;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

public class DbUtil {

	public static Connection getConnection() {
		Connection con = null;
		GetHeader getHeader = new GetHeader();
		try {
			/*Class.forName("com.mysql.jdbc.Driver");
			con = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "root", "My1234");*/
			Class.forName(getHeader.getClassForName());
			con = DriverManager.getConnection(getHeader.getURLLocal(), getHeader.getDatabaseUserName(), getHeader.getDatabasePassword());
		} catch (Exception e) {
			System.out.println(e);
		}
		return con;
	}
}
