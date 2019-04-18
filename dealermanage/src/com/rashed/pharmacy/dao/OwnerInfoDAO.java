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

import com.rashed.pharmacy.model.OwnerInfo;
import com.rashed.pharmacy.util.*;

public class OwnerInfoDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public OwnerInfoDAO(){
		//con  = DbUtil.getConnection();
	}
	
	// MD5 password encrypt [S]
	StringBuilder sb = null;
	String md5Password = "";
	// MD5 password encrypt [E]
	
	public void save(OwnerInfo oi){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO owner_info(owner_id, owner_name, description, owner_type, owner_start_date, father_name, mother_name, nid, dob, occupation, country_id, mobile, email, account_id, home_address, office_address, profession, password, status, created, updated) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
	    	try {
				// MD5 password encrypt [S]
				String password = oi.getPassword();
	
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
	    	
			ps.setString(1, oi.getOwner_id());
			ps.setString(2, oi.getOwner_name());
			ps.setString(3, oi.getDescription());
			ps.setString(4, oi.getOwner_type());
			ps.setString(5, oi.getOwner_start_date());
			ps.setString(6, oi.getFather_name());
			ps.setString(7, oi.getMother_name());
			ps.setString(8, oi.getNid());
			ps.setString(9, oi.getDob());
			ps.setString(10, oi.getOccupation());
			ps.setString(11, oi.getCountry_id());
			ps.setString(12, oi.getMobile());
			ps.setString(13, oi.getEmail());
			ps.setString(14, oi.getAccount_id());
			ps.setString(15, oi.getHome_address());
			ps.setString(16, oi.getOffice_address());
			ps.setString(17, oi.getProfession());
			ps.setString(18, md5Password);
			//ps.setString(18, oi.getPassword());
			ps.setString(19, oi.getStatus());
			ps.setString(20, oi.getCreated());
			ps.setString(21, oi.getUpdated());
			
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
	
	public void delete(String owner_id){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM owner_info WHERE owner_id=?");
			
			ps.setString(1, owner_id);
			
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
	
	public void update(OwnerInfo oi){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE owner_info set owner_name=?, description=?, owner_type=?, father_name=?, "
					+ "mother_name=?, nid=?, dob=?, occupation=?, country_id=?, mobile=?, email=?, account_id=?, home_address=?, office_address=?, "
					+ "profession=?, password=?, status=?, updated=? where owner_id=?");
			
			
			try {
				// MD5 password encrypt [S]
				String password = oi.getPassword();
	
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
			
			ps.setString(1, oi.getOwner_name());
			ps.setString(2, oi.getDescription());
			ps.setString(3, oi.getOwner_type());
			ps.setString(4, oi.getFather_name());
			ps.setString(5, oi.getMother_name());
			ps.setString(6, oi.getNid());
			ps.setString(7, oi.getDob());
			ps.setString(8, oi.getOccupation());
			ps.setString(9, oi.getCountry_id());
			ps.setString(10, oi.getMobile());
			ps.setString(11, oi.getEmail());
			ps.setString(12, oi.getAccount_id());
			ps.setString(13, oi.getHome_address());
			ps.setString(14, oi.getOffice_address());
			ps.setString(15, oi.getProfession());
			//ps.setString(16, oi.getPassword());
			ps.setString(16, md5Password);
			ps.setString(17, oi.getStatus());
			ps.setString(18, oi.getUpdated());
			ps.setString(19, oi.getOwner_id());
			
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
	
	public List<OwnerInfo> getAllOwnerInfo(){
		List<OwnerInfo> list = new ArrayList<OwnerInfo>();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT owner_id, owner_name, description, owner_type, owner_start_date, father_name, mother_name, nid, dob, occupation, country_id, mobile, email, account_id, home_address, office_address, profession, password, status, created, updated FROM owner_info");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				OwnerInfo oi = new OwnerInfo();
				
				oi.setOwner_id(rs.getString(1));
				oi.setOwner_name(rs.getString(2));
				oi.setDescription(rs.getString(3));
				oi.setOwner_type(rs.getString(4));
				oi.setOwner_start_date(rs.getString(5));
				oi.setFather_name(rs.getString(6));
				oi.setMother_name(rs.getString(7));
				oi.setNid(rs.getString(8));
				oi.setDob(rs.getString(9));
				oi.setOccupation(rs.getString(10));
				oi.setCountry_id(rs.getString(11));
				oi.setMobile(rs.getString(12));
				oi.setEmail(rs.getString(13));
				oi.setAccount_id(rs.getString(14));
				oi.setHome_address(rs.getString(15));
				oi.setOffice_address(rs.getString(16));
				oi.setProfession(rs.getString(17));
				oi.setPassword(rs.getString(18));
				oi.setStatus(rs.getString(19));
				oi.setCreated(rs.getString(20));
				oi.setUpdated(rs.getString(21));
				
				list.add(oi);				
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
	
	public OwnerInfo getOwnerInfoById(String owner_id){
		OwnerInfo oi = new OwnerInfo();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT owner_id, owner_name, description, owner_type, owner_start_date, "
					+ "father_name, mother_name, nid, dob, occupation, country_id, mobile, email, account_id, home_address, office_address, profession, "
					+ "password, status, created, updated FROM owner_info where owner_id=?");
			
			ps.setString(1, owner_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				oi.setOwner_id(rs.getString(1));
				oi.setOwner_name(rs.getString(2));
				oi.setDescription(rs.getString(3));
				oi.setOwner_type(rs.getString(4));
				oi.setOwner_start_date(rs.getString(5));
				oi.setFather_name(rs.getString(6));
				oi.setMother_name(rs.getString(7));
				oi.setNid(rs.getString(8));
				oi.setDob(rs.getString(9));
				oi.setOccupation(rs.getString(10));
				oi.setCountry_id(rs.getString(11));
				oi.setMobile(rs.getString(12));
				oi.setEmail(rs.getString(13));
				oi.setAccount_id(rs.getString(14));
				oi.setHome_address(rs.getString(15));
				oi.setOffice_address(rs.getString(16));
				oi.setProfession(rs.getString(17));
				oi.setPassword(rs.getString(18));
				oi.setStatus(rs.getString(19));
				oi.setCreated(rs.getString(20));
				oi.setUpdated(rs.getString(21));
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

		return oi;
	}
	
	// generated auto increment id during add [S]
	public OwnerInfo getOwnerInfoID(){
		OwnerInfo oi = new OwnerInfo();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT owner_id FROM owner_info");
			rs = ps.executeQuery();
			
			int owner_id = 0;
			
			if(rs.next() == false) {
				owner_id = 1000000000;
				owner_id = owner_id+1;
				oi.setOwner_id("OWNR" + String.valueOf(owner_id));
			} else {
				if(rs.last()) {
					String strOwner = rs.getString("owner_id");
					owner_id = Integer.parseInt(strOwner.replaceAll("[^0-9]", ""));
					owner_id = owner_id+1;
					oi.setOwner_id("OWNR" + String.valueOf(owner_id));
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
		
		return oi;
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
	
	public static boolean validate(String owner_id, String password) {
	//public boolean validate(String merchant_branch_id, String password) {
		Connection con = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		boolean status = false;
		try {
			//conn=DbUtil.getConnection();
			con  = DbUtil.getConnection();
			OwnerInfoDAO ddd = new OwnerInfoDAO();
			ps = ddd.con.prepareStatement("SELECT owner_id, owner_name, description, owner_type, owner_start_date, father_name, mother_name, nid, dob, occupation, country_id, mobile, email, account_id, home_address, office_address, profession, password, status, created, updated FROM owner_info where owner_id=? and password=?");
			ps.setString(1, owner_id);
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
