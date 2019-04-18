package com.rashed.pharmacy.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import com.rashed.pharmacy.model.Product;
import com.rashed.pharmacy.model.Requisition;
import com.rashed.pharmacy.util.*;

public class RequisitionDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public RequisitionDAO(){
		//con  = DbUtil.getConnection();
	}
	
	//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
	Date date = new Date();  
	String strDate = formatter.format(date);
	
	public void save(Requisition r){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO requisition(requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO requisition(requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			ps.setString(1, r.getRequisition_id());
			ps.setString(2, r.getCustomer_id());
			ps.setString(3, r.getCustomer_name());
			ps.setString(4, r.getMobile());
			ps.setString(5, r.getProduct_id());
			ps.setString(6, r.getProduct_name());
			ps.setString(7, r.getPack_type());
			ps.setString(8, r.getPack_size());
			ps.setInt(9, r.getPiceces());
			ps.setString(10, r.getBonus_id());
			ps.setString(11, r.getBonus_name());
			ps.setString(12, r.getOrder_pack());
			ps.setInt(13, r.getOrder_quantity());
			ps.setDouble(14, r.getMrp_price());
			ps.setDouble(15, r.getTotal_mrp_price());
			ps.setDouble(16, r.getDiscount_amt());
			ps.setDouble(17, r.getTotal_amount());
			ps.setString(18, r.getNeeded_date_time());
			ps.setString(19, r.getFrom_account_id());
			ps.setString(20, r.getTo_account_id());
			ps.setString(21, r.getSalesman_id());
			ps.setString(22, r.getOrder_status());
			ps.setString(23, r.getDelivery_status());
			ps.setString(24, r.getCreated());
			ps.setString(25, r.getUpdated());
			
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
	
	public void delete(String requisition_id){
		try{
			//PreparedStatement ps = con.prepareStatement("DELETE FROM requisition WHERE requisition_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM requisition WHERE requisition_id=?");
			
			ps.setString(1, requisition_id);
			
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
	
	public void update(Requisition r){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE requisition set customer_id=?, customer_name=?, mobile=?, product_id=?, product_name=?, pack_type=?, pack_size=?, piceces=?, bonus_id=?, bonus_name=?, order_pack=?, order_quantity=?, mrp_price=?, total_mrp_price=?, discount_amt=?, total_amount=?, needed_date_time=?, from_account_id=?, to_account_id=?, salesman_id=?, order_status=?, delivery_status=?, created=?, updated=? where requisition_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE requisition set customer_id=?, customer_name=?, mobile=?, product_id=?, product_name=?, pack_type=?, pack_size=?, piceces=?, bonus_id=?, bonus_name=?, order_pack=?, order_quantity=?, mrp_price=?, total_mrp_price=?, discount_amt=?, total_amount=?, needed_date_time=?, from_account_id=?, to_account_id=?, salesman_id=?, order_status=?, delivery_status=?, created=?, updated=? where requisition_id=?");
			
			ps.setString(1, r.getCustomer_id());
			ps.setString(2, r.getCustomer_name());
			ps.setString(3, r.getMobile());
			ps.setString(4, r.getProduct_id());
			ps.setString(5, r.getProduct_name());
			ps.setString(6, r.getPack_type());
			ps.setString(7, r.getPack_size());
			ps.setInt(8, r.getPiceces());
			ps.setString(9, r.getBonus_id());
			ps.setString(10, r.getBonus_name());
			ps.setString(11, r.getOrder_pack());
			ps.setInt(12, r.getOrder_quantity());
			ps.setDouble(13, r.getMrp_price());
			ps.setDouble(14, r.getTotal_mrp_price());
			ps.setDouble(15, r.getDiscount_amt());
			ps.setDouble(16, r.getTotal_amount());
			ps.setString(17, r.getNeeded_date_time());
			ps.setString(18, r.getFrom_account_id());
			ps.setString(19, r.getTo_account_id());
			ps.setString(20, r.getSalesman_id());
			ps.setString(21, r.getOrder_status());
			ps.setString(22, r.getDelivery_status());
			ps.setString(23, r.getCreated());
			ps.setString(24, r.getUpdated());
			ps.setString(25, r.getRequisition_id());
			
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
	
	public void cancel(String requisition_id){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE requisition set order_status=?, updated=? where requisition_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE requisition set order_status=?, updated=? where requisition_id=?");
			
			ps.setString(1, "C");
			ps.setString(2, strDate);
			ps.setString(3, requisition_id);
			
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
	
	public void approve(String requisition_id){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE requisition set order_status=?, updated=? where requisition_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE requisition set order_status=?, updated=? where requisition_id=?");
			
			ps.setString(1, "A");
			ps.setString(2, strDate);
			ps.setString(3, requisition_id);
			
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
	
	public List<Requisition> getAllRequisition(){
		List<Requisition> list = new ArrayList<Requisition>();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated FROM requisition ORDER BY created DESC");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated FROM requisition ORDER BY created DESC");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				Requisition r = new Requisition();				
				
				r.setRequisition_id(rs.getString(1));
				r.setCustomer_id(rs.getString(2));
				r.setCustomer_name(rs.getString(3));
				r.setMobile(rs.getString(4));
				r.setProduct_id(rs.getString(5));
				r.setProduct_name(rs.getString(6));
				r.setPack_type(rs.getString(7));
				r.setPack_size(rs.getString(8));
				r.setPiceces(rs.getInt(9));
				r.setBonus_id(rs.getString(10));
				r.setBonus_name(rs.getString(11));
				r.setOrder_pack(rs.getString(12));
				r.setOrder_quantity(rs.getInt(13));
				r.setMrp_price(rs.getDouble(14));
				r.setTotal_mrp_price(rs.getDouble(15));
				r.setDiscount_amt(rs.getDouble(16));
				r.setTotal_amount(rs.getDouble(17));
				r.setNeeded_date_time(rs.getString(18));
				r.setFrom_account_id(rs.getString(19));
				r.setTo_account_id(rs.getString(20));
				r.setSalesman_id(rs.getString(21));
				r.setOrder_status(rs.getString(22));
				r.setDelivery_status(rs.getString(23));
				r.setCreated(rs.getString(24));
				r.setUpdated(rs.getString(25));
			
				list.add(r);				
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
	
	public Requisition getRequisitionById(String requisition_id){
		Requisition r = new Requisition();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated FROM requisition where requisition_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated FROM requisition where requisition_id=?");
			
			ps.setString(1, requisition_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				r.setRequisition_id(rs.getString(1));
				r.setCustomer_id(rs.getString(2));
				r.setCustomer_name(rs.getString(3));
				r.setMobile(rs.getString(4));
				r.setProduct_id(rs.getString(5));
				r.setProduct_name(rs.getString(6));
				r.setPack_type(rs.getString(7));
				r.setPack_size(rs.getString(8));
				r.setPiceces(rs.getInt(9));
				r.setBonus_id(rs.getString(10));
				r.setBonus_name(rs.getString(11));
				r.setOrder_pack(rs.getString(12));
				r.setOrder_quantity(rs.getInt(13));
				r.setMrp_price(rs.getDouble(14));
				r.setTotal_mrp_price(rs.getDouble(15));
				r.setDiscount_amt(rs.getDouble(16));
				r.setTotal_amount(rs.getDouble(17));
				r.setNeeded_date_time(rs.getString(18));
				r.setFrom_account_id(rs.getString(19));
				r.setTo_account_id(rs.getString(20));
				r.setSalesman_id(rs.getString(21));
				r.setOrder_status(rs.getString(22));
				r.setDelivery_status(rs.getString(23));
				r.setCreated(rs.getString(24));
				r.setUpdated(rs.getString(25));
				
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

		return r;
	}
	
	// generated auto increment id during add [S]
	public Requisition getRequisitionID(){
		Requisition r = new Requisition();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT requisition_id FROM requisition");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT requisition_id FROM requisition");
			rs = ps.executeQuery();
			
			int requisition_id = 0;
			
			if(rs.next() == false) {
				requisition_id = 1000000000;
				requisition_id = requisition_id+1;
				r.setRequisition_id("REQU" + String.valueOf(requisition_id));
			} else {
				if(rs.last()) {
					String strRequisition = rs.getString("requisition_id");
					requisition_id = Integer.parseInt(strRequisition.replaceAll("[^0-9]", ""));
					requisition_id = requisition_id+1;
					r.setRequisition_id("REQU" + String.valueOf(requisition_id));
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
		
		return r;
	}
	// generated auto increment id during add [E]
	
	// selected other respective id during update [S]
	public Requisition getSelectedOtherID(String requisition_id){
		Requisition r = new Requisition();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT requisition_id, customer_id, product_id, bonus_id, salesman_id, order_status, order_quantity FROM requisition WHERE requisition_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT requisition_id, customer_id, product_id, bonus_id, salesman_id, order_status, order_quantity FROM requisition WHERE requisition_id=?");
			
			ps.setString(1, requisition_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strRequisition = rs.getString("requisition_id");
				String strCustomer = rs.getString("customer_id");
				String strProduct = rs.getString("product_id");
				String strBonus = rs.getString("bonus_id");
				String strSalesman = rs.getString("salesman_id");
				String strOrderStatus = rs.getString("order_status");
				int intOrderQuantity = rs.getInt("order_quantity");
				
				r.setRequisition_id(strRequisition);
				r.setCustomer_id(strCustomer);
				r.setProduct_id(strProduct);
				r.setBonus_id(strBonus);
				r.setSalesman_id(strSalesman);
				r.setOrder_status(strOrderStatus);
				r.setOrder_quantity(intOrderQuantity);
				
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
		
		return r;
	}
	// selected other respective id during update [E]
	
	// get value from more than one table [S]
	/*public Generic getValueFromDifferentTable(String product_id){
		
		Generic g = new Generic();
		
		try{
			
			PreparedStatement ps = con.prepareStatement("SELECT g.generic_id, g.generic_name, g.indications, g.adult_dose, g.child_dose, g.renal_dose, "
					+ "g.administrations, g.contraindications, g.side_effects, g.precautions_warnings, g.pregnancy_category, g.therapeutic_class, "
					+ "g.mode_of_action, g.interaction FROM generic g WHERE g.generic_id = (SELECT p.generic_id FROM product p, generic g "
					+ "WHERE p.generic_id=g.generic_id and p.product_id=?)");
			
			ps.setString(1, product_id);
			
			ResultSet rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strGeneric = rs.getString("generic_id");
				String strGenericName = rs.getString("generic_name");
				String strIndications = rs.getString("indications");
				String strAdultDose = rs.getString("adult_dose");
				String strChildDose = rs.getString("child_dose");
				String strRenalDose = rs.getString("renal_dose");
				String strAdministrations = rs.getString("administrations");
				String strContraindications= rs.getString("contraindications");
				String strSideEffects = rs.getString("side_effects");
				String strPrecautionsWarnings = rs.getString("precautions_warnings");
				String strPregnancyCategory = rs.getString("pregnancy_category");
				String strTherapeuticClass = rs.getString("therapeutic_class");
				String strModeOfAction = rs.getString("mode_of_action");
				String strInteraction = rs.getString("interaction");
				
				g.setGeneric_id(strGeneric);
				g.setGeneric_name(strGenericName);
				g.setIndications(strIndications);
				g.setAdult_dose(strAdultDose);
				g.setChild_dose(strChildDose);
				g.setRenal_dose(strRenalDose);	
				g.setAdministrations(strAdministrations);
				g.setContraindications(strContraindications);
				g.setSide_effects(strSideEffects);
				g.setPrecautions_warnings(strPrecautionsWarnings);
				g.setPregnancy_category(strPregnancyCategory);
				g.setTherapeutic_class(strTherapeuticClass);
				g.setMode_of_action(strModeOfAction);
				g.setInteraction(strInteraction);
			}
			
		} catch(Exception e){
			e.printStackTrace();
		}
		return g;
	}*/
	// get value from more than one table [E]

}
