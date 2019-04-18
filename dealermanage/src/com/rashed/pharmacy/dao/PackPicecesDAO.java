package com.rashed.pharmacy.dao;

import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.rashed.pharmacy.model.PackPiceces;
import com.rashed.pharmacy.util.*;

public class PackPicecesDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public PackPicecesDAO(){
		//con  = DbUtil.getConnection();
	}
	
	
	public void save(PackPiceces pp){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO pack_piceces(pack_piceces_id, pack_type, pack_size, piceces, created, updated) values (?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO pack_piceces(pack_piceces_id, pack_type, pack_size, piceces, created, updated) values (?, ?, ?, ?, ?, ?)");
			
			ps.setString(1, pp.getPack_piceces_id());
			ps.setString(2, pp.getPack_type());
			ps.setString(3, pp.getPack_size());
			ps.setInt(4, pp.getPiceces());
			ps.setString(5, pp.getCreated());
			ps.setString(6, pp.getUpdated());
			
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
	
	public void delete(String pack_piceces_id){
		try{
			//PreparedStatement ps = con.prepareStatement("DELETE FROM pack_piceces WHERE pack_piceces_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM pack_piceces WHERE pack_piceces_id=?");
			
			ps.setString(1, pack_piceces_id);
			
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
	
	public void update(PackPiceces pp){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE pack_piceces set pack_type=?, pack_size=?, piceces=?, created=?, updated=? where pack_piceces_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE pack_piceces set pack_type=?, pack_size=?, piceces=?, created=?, updated=? where pack_piceces_id=?");
			
			ps.setString(1, pp.getPack_type());
			ps.setString(2, pp.getPack_size());
			ps.setInt(3, pp.getPiceces());
			ps.setString(4, pp.getCreated());
			ps.setString(5, pp.getUpdated());
			ps.setString(6, pp.getPack_piceces_id());
			
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
	
	public List<PackPiceces> getAllPackPiceces(){
		List<PackPiceces> list = new ArrayList<PackPiceces>();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT pack_piceces_id, pack_type, pack_size, piceces, created, updated FROM pack_piceces");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT pack_piceces_id, pack_type, pack_size, piceces, created, updated FROM pack_piceces");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				PackPiceces pp = new PackPiceces();
				
				pp.setPack_piceces_id(rs.getString(1));
				pp.setPack_type(rs.getString(2));
				pp.setPack_size(rs.getString(3));
				pp.setPiceces(rs.getInt(4));
				pp.setCreated(rs.getString(5));
				pp.setUpdated(rs.getString(6));
				
				list.add(pp);				
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
	
	public PackPiceces getPackPicecesById(String pack_piceces_id){
		PackPiceces pp = new PackPiceces();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT pack_piceces_id, pack_type, pack_size, piceces, created, updated FROM pack_piceces where pack_piceces_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT pack_piceces_id, pack_type, pack_size, piceces, created, updated FROM pack_piceces where pack_piceces_id=?");
			
			ps.setString(1, pack_piceces_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				pp.setPack_piceces_id(rs.getString(1));
				pp.setPack_type(rs.getString(2));
				pp.setPack_size(rs.getString(3));
				pp.setPiceces(rs.getInt(4));
				pp.setCreated(rs.getString(5));
				pp.setUpdated(rs.getString(6));
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

		return pp;
	}
	
	// generated auto increment id during add [S]
	public PackPiceces getPackPicecesID(){
		PackPiceces pp = new PackPiceces();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT pack_piceces_id FROM pack_piceces");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT pack_piceces_id FROM pack_piceces");
			rs = ps.executeQuery();
			
			int pack_piceces_id = 0;
			
			if(rs.next() == false) {
				pack_piceces_id = 1000000;
				pack_piceces_id = pack_piceces_id+1;
				pp.setPack_piceces_id("PAKPCES" + String.valueOf(pack_piceces_id));
			} else {
				if(rs.last()) {
					String strPackPieces = rs.getString("pack_piceces_id");
					pack_piceces_id = Integer.parseInt(strPackPieces.replaceAll("[^0-9]", ""));
					pack_piceces_id = pack_piceces_id+1;
					pp.setPack_piceces_id("PAKPCES" + String.valueOf(pack_piceces_id));
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
		
		return pp;
	}
	// generated auto increment id during add [E]

}