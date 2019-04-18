package com.rashed.pharmacy.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.rashed.pharmacy.model.Generic;
import com.rashed.pharmacy.util.*;

public class GenericDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public GenericDAO(){
		//con  = DbUtil.getConnection();
	}
	
	
	public void save(Generic g){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO generic(generic_id, generic_name, product_category_id, indications, adult_dose, child_dose, renal_dose, administrations, contraindications, side_effects, precautions_warnings, pregnancy_category, therapeutic_class, mode_of_action, interaction, created, updated) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO generic(generic_id, generic_name, product_category_id, indications, adult_dose, child_dose, renal_dose, administrations, contraindications, side_effects, precautions_warnings, pregnancy_category, therapeutic_class, mode_of_action, interaction, created, updated) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			ps.setString(1, g.getGeneric_id());
			ps.setString(2, g.getGeneric_name());
			ps.setString(3, g.getProduct_category_id());
			ps.setString(4, g.getIndications());
			ps.setString(5, g.getAdult_dose());
			ps.setString(6, g.getChild_dose());
			ps.setString(7, g.getRenal_dose());
			ps.setString(8, g.getAdministrations());
			ps.setString(9, g.getContraindications());
			ps.setString(10, g.getSide_effects());
			ps.setString(11, g.getPrecautions_warnings());
			ps.setString(12, g.getPregnancy_category());
			ps.setString(13, g.getTherapeutic_class());
			ps.setString(14, g.getMode_of_action());
			ps.setString(15, g.getInteraction());
			ps.setString(16, g.getCreated());
			ps.setString(17, g.getUpdated());
			
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
	
	public void delete(String generic_id){
		try{
			//PreparedStatement ps = con.prepareStatement("DELETE FROM generic WHERE generic_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM generic WHERE generic_id=?");
			
			ps.setString(1, generic_id);
			
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
	
	public void update(Generic g){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE generic set generic_name=?, product_category_id=?, indications=?, adult_dose=?, child_dose=?, renal_dose=?, administrations=?, contraindications=?, side_effects=?, precautions_warnings=?, pregnancy_category=?, therapeutic_class=?, mode_of_action=?, interaction=?, created=?, updated=? where generic_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE generic set generic_name=?, product_category_id=?, indications=?, adult_dose=?, child_dose=?, renal_dose=?, administrations=?, contraindications=?, side_effects=?, precautions_warnings=?, pregnancy_category=?, therapeutic_class=?, mode_of_action=?, interaction=?, created=?, updated=? where generic_id=?");
			
			ps.setString(1, g.getGeneric_name());
			ps.setString(2, g.getProduct_category_id());
			ps.setString(3, g.getIndications());
			ps.setString(4, g.getAdult_dose());
			ps.setString(5, g.getChild_dose());
			ps.setString(6, g.getRenal_dose());
			ps.setString(7, g.getAdministrations());
			ps.setString(8, g.getContraindications());
			ps.setString(9, g.getSide_effects());
			ps.setString(10, g.getPrecautions_warnings());
			ps.setString(11, g.getPregnancy_category());
			ps.setString(12, g.getTherapeutic_class());
			ps.setString(13, g.getMode_of_action());
			ps.setString(14, g.getInteraction());
			ps.setString(15, g.getCreated());
			ps.setString(16, g.getUpdated());
			ps.setString(17, g.getGeneric_id());
			
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
	
	public List<Generic> getAllGeneric(){
		List<Generic> list = new ArrayList<Generic>();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT generic_id, generic_name, product_category_id, indications, adult_dose, child_dose, renal_dose, administrations, contraindications, side_effects, precautions_warnings, pregnancy_category, therapeutic_class, mode_of_action, interaction, created, updated FROM generic");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT generic_id, generic_name, product_category_id, indications, adult_dose, child_dose, renal_dose, administrations, contraindications, side_effects, precautions_warnings, pregnancy_category, therapeutic_class, mode_of_action, interaction, created, updated FROM generic");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				Generic g = new Generic();				
				
				g.setGeneric_id(rs.getString(1));
				g.setGeneric_name(rs.getString(2));
				g.setProduct_category_id(rs.getString(3));
				g.setIndications(rs.getString(4));
				g.setAdult_dose(rs.getString(5));
				g.setChild_dose(rs.getString(6));
				g.setRenal_dose(rs.getString(7));
				g.setAdministrations(rs.getString(8));
				g.setContraindications(rs.getString(9));
				g.setSide_effects(rs.getString(10));
				g.setPrecautions_warnings(rs.getString(11));
				g.setPregnancy_category(rs.getString(12));
				g.setTherapeutic_class(rs.getString(13));
				g.setMode_of_action(rs.getString(14));
				g.setInteraction(rs.getString(15));
				g.setCreated(rs.getString(16));
				g.setUpdated(rs.getString(17));
				
				list.add(g);				
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
	
	public Generic getGenericById(String generic_id){
		Generic g = new Generic();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT generic_id, generic_name, product_category_id, indications, adult_dose, child_dose, renal_dose, administrations, contraindications, side_effects, precautions_warnings, pregnancy_category, therapeutic_class, mode_of_action, interaction, created, updated FROM generic where generic_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT generic_id, generic_name, product_category_id, indications, adult_dose, child_dose, renal_dose, administrations, contraindications, side_effects, precautions_warnings, pregnancy_category, therapeutic_class, mode_of_action, interaction, created, updated FROM generic where generic_id=?");
			
			ps.setString(1, generic_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				g.setGeneric_id(rs.getString(1));
				g.setGeneric_name(rs.getString(2));
				g.setProduct_category_id(rs.getString(3));
				g.setIndications(rs.getString(4));
				g.setAdult_dose(rs.getString(5));
				g.setChild_dose(rs.getString(6));
				g.setRenal_dose(rs.getString(7));
				g.setAdministrations(rs.getString(8));
				g.setContraindications(rs.getString(9));
				g.setSide_effects(rs.getString(10));
				g.setPrecautions_warnings(rs.getString(11));
				g.setPregnancy_category(rs.getString(12));
				g.setTherapeutic_class(rs.getString(13));
				g.setMode_of_action(rs.getString(14));
				g.setInteraction(rs.getString(15));
				g.setCreated(rs.getString(16));
				g.setUpdated(rs.getString(17));
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

		return g;
	}
	
	// generated auto increment id during add [S]
	public Generic getGenericID(){
		Generic g = new Generic();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT generic_id FROM generic");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT generic_id FROM generic");
			rs = ps.executeQuery();
			
			int generic_id = 0;
			
			if(rs.next() == false) {
				generic_id = 10000000;
				generic_id = generic_id+1;
				g.setGeneric_id("GENRIC" + String.valueOf(generic_id));
			} else {
				if(rs.last()) {
					String strProdCat = rs.getString("generic_id");
					generic_id = Integer.parseInt(strProdCat.replaceAll("[^0-9]", ""));
					generic_id = generic_id+1;
					g.setGeneric_id("GENRIC" + String.valueOf(generic_id));
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
		
		return g;
	}
	// generated auto increment id during add [E]
	
	// selected other respective id during update [S]
	public Generic getSelectedOtherID(String generic_id){
		Generic g = new Generic();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT generic_id, product_category_id FROM generic WHERE generic_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT generic_id, product_category_id FROM generic WHERE generic_id=?");
			
			ps.setString(1, generic_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strGeneric = rs.getString("generic_id");
				String strProductCategory = rs.getString("product_category_id");
				
				g.setGeneric_id(strGeneric);
				g.setProduct_category_id(strProductCategory);
				
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
		
		return g;
	}
	// selected other respective id during update [E]

}
