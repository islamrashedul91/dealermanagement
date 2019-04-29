package com.rashed.pharmacy.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

import com.rashed.pharmacy.model.Sms;
import com.rashed.pharmacy.util.*;

public class SmsDAO {
	
	private Connection con;
	private static Connection conn;
	
	public SmsDAO(){
		con  = DbUtil.getConnection();
	}
	
	// MD5 password encrypt [S]
	StringBuilder sb = null;
	String md5Password = "";
	// MD5 password encrypt [E]
	
	public void save(Sms s){
		try{
			PreparedStatement ps = con.prepareStatement("INSERT INTO sms(delivery_status, mobile, email, sms_body, description, created, updated) values (?, ?, ?, ?, ?, ?, ?)");
	    	
			ps.setString(1, s.getDelivery_status());
			ps.setString(2, s.getMobile());
			ps.setString(3, s.getEmail());
			ps.setString(4, s.getSms_body());
			ps.setString(5, s.getDescription());
			ps.setString(6, s.getCreated());
			ps.setString(7, s.getUpdated());
			
			ps.executeUpdate();
		} catch(Exception e){
			e.printStackTrace();
		}
	}

}
