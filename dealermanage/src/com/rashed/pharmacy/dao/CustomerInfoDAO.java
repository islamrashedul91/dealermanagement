package com.rashed.pharmacy.dao;

import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;




//QRCodeGenerator [S]
import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Path;
//QRCodeGenerator [E]




import com.rashed.pharmacy.model.CustomerInfo;
import com.rashed.pharmacy.model.Requisition;
/*import com.rashed.pharmacy.util.DbUtil;*/
import com.rashed.pharmacy.util.*;

public class CustomerInfoDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public CustomerInfoDAO(){
		//con  = DbUtil.getConnection();
	}
	
	// MD5 password encrypt [S]
	StringBuilder sb = null;
	String md5Password = "";
	// MD5 password encrypt [E]
	
	public void save(CustomerInfo ci){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO customer_info(customer_id, customer_name, customer_desc, customer_type, customer_start_date, father_name, mother_name, nid, dob, occupation, country_id, mobile, email, account_id, home_address, office_address, profession, password, status, created, updated) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO customer_info(customer_id, customer_name, customer_desc, customer_type, customer_start_date, father_name, mother_name, nid, dob, occupation, country_id, mobile, email, account_id, home_address, office_address, profession, password, status, created, updated) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
	    	try {
				// MD5 password encrypt [S]
				String password = ci.getPassword();
	
		        MessageDigest md = MessageDigest.getInstance("MD5");
		        byte[] hashInBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
	
		        sb = new StringBuilder();
		        for (byte b : hashInBytes) {
		            sb.append(String.format("%02x", b));
		        }
		        md5Password = sb.toString();
		        // MD5 password encrypt [S]
	    	} catch (Exception e){
	    		e.printStackTrace();
	    	}	    	
	    	
			ps.setString(1, ci.getCustomer_id());
			ps.setString(2, ci.getCustomer_name());
			ps.setString(3, ci.getCustomer_desc());
			ps.setString(4, ci.getCustomer_type());
			ps.setString(5, ci.getCustomer_start_date());
			ps.setString(6, ci.getFather_name());
			ps.setString(7, ci.getMother_name());
			ps.setString(8, ci.getNid());
			ps.setString(9, ci.getDob());
			ps.setString(10, ci.getOccupation());
			ps.setString(11, ci.getCountry_id());
			ps.setString(12, ci.getMobile());
			ps.setString(13, ci.getEmail());
			ps.setString(14, ci.getAccount_id());
			ps.setString(15, ci.getHome_address());
			ps.setString(16, ci.getOffice_address());
			ps.setString(17, ci.getProfession());
			ps.setString(18, md5Password);
			//ps.setString(18, ci.getPassword());
			ps.setString(19, ci.getStatus());
			ps.setString(20, ci.getCreated());
			ps.setString(21, ci.getUpdated());
			
			ps.executeUpdate();
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public void delete(String customer_id){
		try{
			//PreparedStatement ps = con.prepareStatement("DELETE FROM customer_info WHERE customer_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM customer_info WHERE customer_id=?");
			
			ps.setString(1, customer_id);
			
			ps.executeUpdate();
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public void update(CustomerInfo ci){
		try{
			/*PreparedStatement ps = con.prepareStatement("UPDATE customer_info set customer_name=?, customer_desc=?, customer_type=?, father_name=?, "
					+ "mother_name=?, nid=?, dob=?, occupation=?, country_id=?, mobile=?, email=?, account_id=?, home_address=?, office_address=?, "
					+ "profession=?, password=?, status=?, updated=? where customer_id=?");*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE customer_info set customer_name=?, customer_desc=?, customer_type=?, father_name=?, "
					+ "mother_name=?, nid=?, dob=?, occupation=?, country_id=?, mobile=?, email=?, account_id=?, home_address=?, office_address=?, "
					+ "profession=?, password=?, status=?, updated=? where customer_id=?");
			
			
			try {
				// MD5 password encrypt [S]
				String password = ci.getPassword();
	
		        MessageDigest md = MessageDigest.getInstance("MD5");
		        byte[] hashInBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
	
		        sb = new StringBuilder();
		        for (byte b : hashInBytes) {
		            sb.append(String.format("%02x", b));
		        }
		        md5Password = sb.toString();
		        // MD5 password encrypt [S]
	    	} catch (Exception e){
	    		e.printStackTrace();
	    	}
			
			ps.setString(1, ci.getCustomer_name());
			ps.setString(2, ci.getCustomer_desc());
			ps.setString(3, ci.getCustomer_type());
			ps.setString(4, ci.getFather_name());
			ps.setString(5, ci.getMother_name());
			ps.setString(6, ci.getNid());
			ps.setString(7, ci.getDob());
			ps.setString(8, ci.getOccupation());
			ps.setString(9, ci.getCountry_id());
			ps.setString(10, ci.getMobile());
			ps.setString(11, ci.getEmail());
			ps.setString(12, ci.getAccount_id());
			ps.setString(13, ci.getHome_address());
			ps.setString(14, ci.getOffice_address());
			ps.setString(15, ci.getProfession());
			//ps.setString(16, ci.getPassword());
			ps.setString(16, md5Password);
			ps.setString(17, ci.getStatus());
			ps.setString(18, ci.getUpdated());
			ps.setString(19, ci.getCustomer_id());
			
			ps.executeUpdate();		
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	public List<CustomerInfo> getAllCustomerInfo(){
		List<CustomerInfo> list = new ArrayList<CustomerInfo>();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT customer_id, customer_name, customer_desc, customer_type, customer_start_date, father_name, mother_name, nid, dob, occupation, country_id, mobile, email, account_id, home_address, office_address, profession, password, status, created, updated FROM customer_info");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT customer_id, customer_name, customer_desc, customer_type, customer_start_date, father_name, mother_name, nid, dob, occupation, country_id, mobile, email, account_id, home_address, office_address, profession, password, status, created, updated FROM customer_info");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				CustomerInfo ci = new CustomerInfo();
				
				ci.setCustomer_id(rs.getString(1));
				ci.setCustomer_name(rs.getString(2));
				ci.setCustomer_desc(rs.getString(3));
				ci.setCustomer_type(rs.getString(4));
				ci.setCustomer_start_date(rs.getString(5));
				ci.setFather_name(rs.getString(6));
				ci.setMother_name(rs.getString(7));
				ci.setNid(rs.getString(8));
				ci.setDob(rs.getString(9));
				ci.setOccupation(rs.getString(10));
				ci.setCountry_id(rs.getString(11));
				ci.setMobile(rs.getString(12));
				ci.setEmail(rs.getString(13));
				ci.setAccount_id(rs.getString(14));
				ci.setHome_address(rs.getString(15));
				ci.setOffice_address(rs.getString(16));
				ci.setProfession(rs.getString(17));
				ci.setPassword(rs.getString(18));
				ci.setStatus(rs.getString(19));
				ci.setCreated(rs.getString(20));
				ci.setUpdated(rs.getString(21));
				
				list.add(ci);				
			}
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs != null){
				try {
					rs.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
		return list;
	}
	
	public CustomerInfo getCustomerInfoById(String customer_id){
		CustomerInfo ci = new CustomerInfo();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT customer_id, customer_name, customer_desc, customer_type, customer_start_date, "
					+ "father_name, mother_name, nid, dob, occupation, country_id, mobile, email, account_id, home_address, office_address, profession, "
					+ "password, status, created, updated FROM customer_info where customer_id=?");*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT customer_id, customer_name, customer_desc, customer_type, customer_start_date, "
					+ "father_name, mother_name, nid, dob, occupation, country_id, mobile, email, account_id, home_address, office_address, profession, "
					+ "password, status, created, updated FROM customer_info where customer_id=?");
			
			ps.setString(1, customer_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				ci.setCustomer_id(rs.getString(1));
				ci.setCustomer_name(rs.getString(2));
				ci.setCustomer_desc(rs.getString(3));
				ci.setCustomer_type(rs.getString(4));
				ci.setCustomer_start_date(rs.getString(5));
				ci.setFather_name(rs.getString(6));
				ci.setMother_name(rs.getString(7));
				ci.setNid(rs.getString(8));
				ci.setDob(rs.getString(9));
				ci.setOccupation(rs.getString(10));
				ci.setCountry_id(rs.getString(11));
				ci.setMobile(rs.getString(12));
				ci.setEmail(rs.getString(13));
				ci.setAccount_id(rs.getString(14));
				ci.setHome_address(rs.getString(15));
				ci.setOffice_address(rs.getString(16));
				ci.setProfession(rs.getString(17));
				ci.setPassword(rs.getString(18));
				ci.setStatus(rs.getString(19));
				ci.setCreated(rs.getString(20));
				ci.setUpdated(rs.getString(21));
			}
		} catch (Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs != null){
				try {
					rs.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}

		return ci;
	}
	
	// generated auto increment id during add [S]
	public CustomerInfo getCustomerInfoID(){
		CustomerInfo ci = new CustomerInfo();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT customer_id FROM customer_info");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT customer_id FROM customer_info");
			rs = ps.executeQuery();
			
			int customer_id = 0;
			
			if(rs.next() == false) {
				customer_id = 1000000000;
				customer_id = customer_id+1;
				ci.setCustomer_id("CUST" + String.valueOf(customer_id));
			} else {
				if(rs.last()) {
					String strRequisition = rs.getString("customer_id");
					customer_id = Integer.parseInt(strRequisition.replaceAll("[^0-9]", ""));
					customer_id = customer_id+1;
					ci.setCustomer_id("CUST" + String.valueOf(customer_id));
				}
			}
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs != null){
				try {
					rs.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
		
		return ci;
	}
	// generated auto increment id during add [E]
	
	// QRCodeGenerator [S]
	public void generateQRCodeImage(String text, int width, int height, String filePath)
            throws WriterException, IOException {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(text, BarcodeFormat.QR_CODE, width, height);

        Path path = FileSystems.getDefault().getPath(filePath);
        MatrixToImageWriter.writeToPath(bitMatrix, "PNG", path);
    }
	// QRCodeGenerator [E]
	
	public static boolean validate(String customer_id, String password) {
	//public boolean validate(String merchant_branch_id, String password) {
		Connection con = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		boolean status = false;
		try {
			//conn=DbUtil.getConnection();
			con  = DbUtil.getConnection();
			CustomerInfoDAO ddd = new CustomerInfoDAO();
			ps = ddd.con.prepareStatement("SELECT customer_id, customer_name, customer_desc, customer_type, customer_start_date, father_name, mother_name, nid, dob, occupation, country_id, mobile, email, account_id, home_address, office_address, profession, password, status, created, updated FROM customer_info where customer_id=? and password=?");
			ps.setString(1, customer_id);
			ps.setString(2, password);
			rs = ps.executeQuery();
			status = rs.next();
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con != null){
				try {
					con.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps != null){
				try {
					ps.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs != null){
				try {
					rs.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
		return status;
	}

}
