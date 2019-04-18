package com.rashed.pharmacy.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.rashed.pharmacy.model.SalesmanInfo;
import com.rashed.pharmacy.model.Requisition;
import com.rashed.pharmacy.util.*;

public class SalesmanInfoDAO {
	
	private Connection con;
	private static Connection conn;
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public SalesmanInfoDAO(){
		//con  = DbUtil.getConnection();
	}
	
	public void save(SalesmanInfo smi){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO salesman_info(salesman_id, salesman_name, salesman_desc, salesman_type, salesman_start_date, salesman_position, father_name, mother_name, nid, dob, occupation, home_address, office_address, country_id, mobile, email, account_id, created, updated, status) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO salesman_info(salesman_id, salesman_name, salesman_desc, salesman_type, salesman_start_date, salesman_position, father_name, mother_name, nid, dob, occupation, home_address, office_address, country_id, mobile, email, account_id, created, updated, status) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			ps.setString(1, smi.getSalesman_id());
			ps.setString(2, smi.getSalesman_name());
			ps.setString(3, smi.getSalesman_desc());
			ps.setString(4, smi.getSalesman_type());
			ps.setString(5, smi.getSalesman_start_date());
			ps.setString(6, smi.getSalesman_position());
			ps.setString(7, smi.getFather_name());
			ps.setString(8, smi.getMother_name());
			ps.setString(9, smi.getNid());
			ps.setString(10, smi.getDob());
			ps.setString(11, smi.getOccupation());
			ps.setString(12, smi.getHome_address());
			ps.setString(13, smi.getOffice_address());
			ps.setString(14, smi.getCountry_id());
			ps.setString(15, smi.getMobile());
			ps.setString(16, smi.getEmail());
			ps.setString(17, smi.getAccount_id());
			ps.setString(18, smi.getCreated());
			ps.setString(19, smi.getUpdated());
			ps.setString(20, smi.getStatus());
			
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
	
	public void delete(String salesman_id){
		try{
			//PreparedStatement ps = con.prepareStatement("DELETE FROM salesman_info WHERE salesman_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM salesman_info WHERE salesman_id=?");
			
			ps.setString(1, salesman_id);
			
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
	
	public void update(SalesmanInfo smi){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE salesman_info set salesman_name=?, salesman_desc=?, salesman_type=?, salesman_start_date=?, salesman_position=?, father_name=?, mother_name=?, nid=?, dob=?, occupation=?, home_address=?, office_address=?, country_id=?, mobile=?, email=?, account_id=?, created=?, updated=?, status=? where salesman_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE salesman_info set salesman_name=?, salesman_desc=?, salesman_type=?, salesman_start_date=?, salesman_position=?, father_name=?, mother_name=?, nid=?, dob=?, occupation=?, home_address=?, office_address=?, country_id=?, mobile=?, email=?, account_id=?, created=?, updated=?, status=? where salesman_id=?");
			
			ps.setString(1, smi.getSalesman_name());
			ps.setString(2, smi.getSalesman_desc());
			ps.setString(3, smi.getSalesman_type());
			ps.setString(4, smi.getSalesman_start_date());
			ps.setString(5, smi.getSalesman_position());
			ps.setString(6, smi.getFather_name());
			ps.setString(7, smi.getMother_name());
			ps.setString(8, smi.getNid());
			ps.setString(9, smi.getDob());
			ps.setString(10, smi.getOccupation());
			ps.setString(11, smi.getHome_address());
			ps.setString(12, smi.getOffice_address());
			ps.setString(13, smi.getCountry_id());
			ps.setString(14, smi.getMobile());
			ps.setString(15, smi.getEmail());
			ps.setString(16, smi.getAccount_id());
			ps.setString(17, smi.getCreated());
			ps.setString(18, smi.getUpdated());
			ps.setString(19, smi.getStatus());
			ps.setString(20, smi.getSalesman_id());
			
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
	
	public List<SalesmanInfo> getAllSalesmanInfo(){
		List<SalesmanInfo> list = new ArrayList<SalesmanInfo>();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT salesman_id, salesman_name, salesman_desc, salesman_type, salesman_start_date, salesman_position, father_name, mother_name, nid, dob, occupation, home_address, office_address, country_id, mobile, email, account_id, created, updated, status FROM salesman_info");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT salesman_id, salesman_name, salesman_desc, salesman_type, salesman_start_date, salesman_position, father_name, mother_name, nid, dob, occupation, home_address, office_address, country_id, mobile, email, account_id, created, updated, status FROM salesman_info");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				SalesmanInfo smi = new SalesmanInfo();
				
				smi.setSalesman_id(rs.getString(1));
				smi.setSalesman_name(rs.getString(2));
				smi.setSalesman_desc(rs.getString(3));
				smi.setSalesman_type(rs.getString(4));
				smi.setSalesman_start_date(rs.getString(5));
				smi.setSalesman_position(rs.getString(6));
				smi.setFather_name(rs.getString(7));
				smi.setMother_name(rs.getString(8));
				smi.setNid(rs.getString(9));
				smi.setDob(rs.getString(10));
				smi.setOccupation(rs.getString(11));
				smi.setHome_address(rs.getString(12));
				smi.setOffice_address(rs.getString(13));
				smi.setCountry_id(rs.getString(14));
				smi.setMobile(rs.getString(15));
				smi.setEmail(rs.getString(16));
				smi.setAccount_id(rs.getString(17));
				smi.setCreated(rs.getString(18));
				smi.setUpdated(rs.getString(19));
				smi.setStatus(rs.getString(20));
				
				list.add(smi);				
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
	
	public SalesmanInfo getSalesmanInfoById(String salesman_id){
		SalesmanInfo smi = new SalesmanInfo();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT salesman_id, salesman_name, salesman_desc, salesman_type, salesman_start_date, salesman_position, father_name, mother_name, nid, dob, occupation, home_address, office_address, country_id, mobile, email, account_id, created, updated, status FROM salesman_info where salesman_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT salesman_id, salesman_name, salesman_desc, salesman_type, salesman_start_date, salesman_position, father_name, mother_name, nid, dob, occupation, home_address, office_address, country_id, mobile, email, account_id, created, updated, status FROM salesman_info where salesman_id=?");
			
			ps.setString(1, salesman_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				smi.setSalesman_id(rs.getString(1));
				smi.setSalesman_name(rs.getString(2));
				smi.setSalesman_desc(rs.getString(3));
				smi.setSalesman_type(rs.getString(4));
				smi.setSalesman_start_date(rs.getString(5));
				smi.setSalesman_position(rs.getString(6));
				smi.setFather_name(rs.getString(7));
				smi.setMother_name(rs.getString(8));
				smi.setNid(rs.getString(9));
				smi.setDob(rs.getString(10));
				smi.setOccupation(rs.getString(11));
				smi.setHome_address(rs.getString(12));
				smi.setOffice_address(rs.getString(13));
				smi.setCountry_id(rs.getString(14));
				smi.setMobile(rs.getString(15));
				smi.setEmail(rs.getString(16));
				smi.setAccount_id(rs.getString(17));
				smi.setCreated(rs.getString(18));
				smi.setUpdated(rs.getString(19));
				smi.setStatus(rs.getString(20));
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

		return smi;
	}
	
	// generated auto increment id during add [S]
	public SalesmanInfo getSalesmanInfoID(){
		SalesmanInfo smi = new SalesmanInfo();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT salesman_id FROM salesman_info");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT salesman_id FROM salesman_info");
			rs = ps.executeQuery();
			
			int salesman_id = 0;
			
			if(rs.next() == false) {
				salesman_id = 1000000000;
				salesman_id = salesman_id+1;
				smi.setSalesman_id("SMAN" + String.valueOf(salesman_id));
			} else {
				if(rs.last()) {
					String strSalesman = rs.getString("salesman_id");
					salesman_id = Integer.parseInt(strSalesman.replaceAll("[^0-9]", ""));
					salesman_id = salesman_id+1;
					smi.setSalesman_id("SMAN" + String.valueOf(salesman_id));
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
		
		return smi;
	}
	// generated auto increment id during add [E]
}
