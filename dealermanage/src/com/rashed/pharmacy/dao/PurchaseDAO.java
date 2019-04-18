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
import com.rashed.pharmacy.model.Purchase;
import com.rashed.pharmacy.util.*;

public class PurchaseDAO {
	
	private Connection con;
	private static Connection conn;
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public PurchaseDAO(){
		//con  = DbUtil.getConnection();
	}
	
	//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
	Date date = new Date();  
	String strDate = formatter.format(date);
	
	public void save(Purchase p){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO purchase(purchase_id, purchase_type, requisition_id, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, rate_per_piceces, rate_per_box, tp_price, total_tp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO purchase(purchase_id, purchase_type, requisition_id, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, rate_per_piceces, rate_per_box, tp_price, total_tp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			ps.setString(1, p.getPurchase_id());
			ps.setString(2, p.getPurchase_type());
			ps.setString(3, p.getRequisition_id());
			ps.setString(4, p.getProduct_id());
			ps.setString(5, p.getProduct_name());
			ps.setString(6, p.getPack_type());
			ps.setString(7, p.getPack_size());
			ps.setInt(8, p.getPiceces());
			ps.setString(9, p.getBonus_id());
			ps.setString(10, p.getBonus_name());
			ps.setString(11, p.getOrder_pack());
			ps.setInt(12, p.getOrder_quantity());
			ps.setDouble(13, p.getRate_per_piceces());
			ps.setDouble(14, p.getRate_per_box());
			ps.setDouble(15, p.getTp_price());
			ps.setDouble(16, p.getTotal_tp_price());
			ps.setDouble(17, p.getDiscount_amt());
			ps.setDouble(18, p.getTotal_amount());
			ps.setString(19, p.getNeeded_date_time());
			ps.setString(20, p.getFrom_account_id());
			ps.setString(21, p.getTo_account_id());
			ps.setString(22, p.getOrder_status());
			ps.setString(23, p.getDelivery_status());
			ps.setString(24, p.getCreated());
			ps.setString(25, p.getUpdated());
			ps.setString(26, p.getCreated_by());
			ps.setString(27, p.getUpdated_by());
			
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
	
	public void delete(String purchase_id){
		try{
			//PreparedStatement ps = con.prepareStatement("DELETE FROM purchase WHERE purchase_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM purchase WHERE purchase_id=?");
			
			ps.setString(1, purchase_id);
			
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
	
	public void update(Purchase p){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE purchase set purchase_type=?, requisition_id=?, product_id=?, product_name=?, pack_type=?, pack_size=?, piceces=?, bonus_id=?, bonus_name=?, order_pack=?, order_quantity=?, rate_per_piceces=?, rate_per_box=?, tp_price=?, total_tp_price=?, discount_amt=?, total_amount=?, needed_date_time=?, from_account_id=?, to_account_id=?, order_status=?, delivery_status=?, created=?, updated=?, created_by=?, updated_by=? where purchase_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE purchase set purchase_type=?, requisition_id=?, product_id=?, product_name=?, pack_type=?, pack_size=?, piceces=?, bonus_id=?, bonus_name=?, order_pack=?, order_quantity=?, rate_per_piceces=?, rate_per_box=?, tp_price=?, total_tp_price=?, discount_amt=?, total_amount=?, needed_date_time=?, from_account_id=?, to_account_id=?, order_status=?, delivery_status=?, created=?, updated=?, created_by=?, updated_by=? where purchase_id=?");
			
			ps.setString(1, p.getPurchase_type());
			ps.setString(2, p.getRequisition_id());
			ps.setString(3, p.getProduct_id());
			ps.setString(4, p.getProduct_name());
			ps.setString(5, p.getPack_type());
			ps.setString(6, p.getPack_size());
			ps.setInt(7, p.getPiceces());
			ps.setString(8, p.getBonus_id());
			ps.setString(9, p.getBonus_name());
			ps.setString(10, p.getOrder_pack());
			ps.setInt(11, p.getOrder_quantity());
			ps.setDouble(12, p.getRate_per_piceces());
			ps.setDouble(13, p.getRate_per_box());
			ps.setDouble(14, p.getTp_price());
			ps.setDouble(15, p.getTotal_tp_price());
			ps.setDouble(16, p.getDiscount_amt());
			ps.setDouble(17, p.getTotal_amount());
			ps.setString(18, p.getNeeded_date_time());
			ps.setString(19, p.getFrom_account_id());
			ps.setString(20, p.getTo_account_id());
			ps.setString(21, p.getOrder_status());
			ps.setString(22, p.getDelivery_status());
			ps.setString(23, p.getCreated());
			ps.setString(24, p.getUpdated());
			ps.setString(25, p.getCreated_by());
			ps.setString(26, p.getUpdated_by());
			ps.setString(27, p.getPurchase_id());
			
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
	
	public void cancel(String purchase_id){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE purchase set order_status=?, updated=? where purchase_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE purchase set order_status=?, updated=? where purchase_id=?");
			
			ps.setString(1, "C");
			ps.setString(2, strDate);
			ps.setString(3, purchase_id);
			
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
	
	public void approve(String purchase_id){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE purchase set order_status=?, updated=? where purchase_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE purchase set order_status=?, updated=? where purchase_id=?");
			
			ps.setString(1, "A");
			ps.setString(2, strDate);
			ps.setString(3, purchase_id);
			
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
	
	public void receiveApprove(String purchase_id){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE purchase set delivery_status=?, updated=? where purchase_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE purchase set delivery_status=?, updated=? where purchase_id=?");
			
			ps.setString(1, "D");
			ps.setString(2, strDate);
			ps.setString(3, purchase_id);
			
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
	
	public void deliveryReturn(String purchase_id){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE purchase set delivery_status=?, updated=? where purchase_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE purchase set delivery_status=?, updated=? where purchase_id=?");
			
			ps.setString(1, "R");
			ps.setString(2, strDate);
			ps.setString(3, purchase_id);
			
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
	
	public List<Purchase> getAllPurchase(){
		List<Purchase> list = new ArrayList<Purchase>();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT purchase_id, purchase_type, requisition_id, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, rate_per_piceces, rate_per_box, tp_price, total_tp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, order_status, delivery_status, created, updated, created_by, updated_by FROM purchase ORDER BY created DESC");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_id, purchase_type, requisition_id, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, rate_per_piceces, rate_per_box, tp_price, total_tp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, order_status, delivery_status, created, updated, created_by, updated_by FROM purchase ORDER BY created DESC");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				Purchase p = new Purchase();				
				
				p.setPurchase_id(rs.getString(1));
				p.setPurchase_type(rs.getString(2));
				p.setRequisition_id(rs.getString(3));
				p.setProduct_id(rs.getString(4));
				p.setProduct_name(rs.getString(5));
				p.setPack_type(rs.getString(6));
				p.setPack_size(rs.getString(7));
				p.setPiceces(rs.getInt(8));
				p.setBonus_id(rs.getString(9));
				p.setBonus_name(rs.getString(10));
				p.setOrder_pack(rs.getString(11));
				p.setOrder_quantity(rs.getInt(12));
				p.setRate_per_piceces(rs.getDouble(13));
				p.setRate_per_box(rs.getDouble(14));
				p.setTp_price(rs.getDouble(15));
				p.setTotal_tp_price(rs.getDouble(16));
				p.setDiscount_amt(rs.getDouble(17));
				p.setTotal_amount(rs.getDouble(18));
				p.setNeeded_date_time(rs.getString(19));
				p.setFrom_account_id(rs.getString(20));
				p.setTo_account_id(rs.getString(21));
				p.setOrder_status(rs.getString(22));
				p.setDelivery_status(rs.getString(23));
				p.setCreated(rs.getString(24));
				p.setUpdated(rs.getString(25));
				p.setCreated_by(rs.getString(26));
				p.setUpdated_by(rs.getString(27));
			
				list.add(p);				
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
	
	public Purchase getPurchaseById(String purchase_id){
		Purchase p = new Purchase();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT purchase_id, purchase_type, requisition_id, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, rate_per_piceces, rate_per_box, tp_price, total_tp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, order_status, delivery_status, created, updated, created_by, updated_by FROM purchase where purchase_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_id, purchase_type, requisition_id, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, rate_per_piceces, rate_per_box, tp_price, total_tp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, order_status, delivery_status, created, updated, created_by, updated_by FROM purchase where purchase_id=?");
			
			ps.setString(1, purchase_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				p.setPurchase_id(rs.getString(1));
				p.setPurchase_type(rs.getString(2));
				p.setRequisition_id(rs.getString(3));
				p.setProduct_id(rs.getString(4));
				p.setProduct_name(rs.getString(5));
				p.setPack_type(rs.getString(6));
				p.setPack_size(rs.getString(7));
				p.setPiceces(rs.getInt(8));
				p.setBonus_id(rs.getString(9));
				p.setBonus_name(rs.getString(10));
				p.setOrder_pack(rs.getString(11));
				p.setOrder_quantity(rs.getInt(12));
				p.setRate_per_piceces(rs.getDouble(13));
				p.setRate_per_box(rs.getDouble(14));
				p.setTp_price(rs.getDouble(15));
				p.setTotal_tp_price(rs.getDouble(16));
				p.setDiscount_amt(rs.getDouble(17));
				p.setTotal_amount(rs.getDouble(18));
				p.setNeeded_date_time(rs.getString(19));
				p.setFrom_account_id(rs.getString(20));
				p.setTo_account_id(rs.getString(21));
				p.setOrder_status(rs.getString(22));
				p.setDelivery_status(rs.getString(23));
				p.setCreated(rs.getString(24));
				p.setUpdated(rs.getString(25));
				p.setCreated_by(rs.getString(26));
				p.setUpdated_by(rs.getString(27));
				
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

		return p;
	}
	
	// generated auto increment id during add [S]
	public Purchase getPurchaseID(){
		Purchase r = new Purchase();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT purchase_id FROM purchase");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_id FROM purchase");
			rs = ps.executeQuery();
			
			int purchase_id = 0;
			
			if(rs.next() == false) {
				purchase_id = 1000000000;
				purchase_id = purchase_id+1;
				r.setPurchase_id("PRCH" + String.valueOf(purchase_id));
			} else {
				if(rs.last()) {
					String strPurchase = rs.getString("purchase_id");
					purchase_id = Integer.parseInt(strPurchase.replaceAll("[^0-9]", ""));
					purchase_id = purchase_id+1;
					r.setPurchase_id("PRCH" + String.valueOf(purchase_id));
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
	public Purchase getSelectedOtherID(String purchase_id){
		Purchase p = new Purchase();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT purchase_id, requisition_id, product_id, bonus_id, order_status, delivery_status, "
					+ "order_quantity, tp_price, total_tp_price, discount_amt, total_amount, from_account_id, to_account_id "
					+ "FROM purchase WHERE purchase_id=?");*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_id, requisition_id, product_id, bonus_id, order_status, delivery_status, "
					+ "order_quantity, tp_price, total_tp_price, discount_amt, total_amount, from_account_id, to_account_id "
					+ "FROM purchase WHERE purchase_id=?");
			
			ps.setString(1, purchase_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strPurchase = rs.getString("purchase_id");
				String strRequisition = rs.getString("requisition_id");
				String strProduct = rs.getString("product_id");
				String strBonus = rs.getString("bonus_id");
				String strOrderStatus = rs.getString("order_status");
				String strDeliveryStatus = rs.getString("delivery_status");
				int intOrderQuantity = rs.getInt("order_quantity");
				double doubleTpPrice = rs.getDouble("tp_price");
				double doubleTotalTpPrice = rs.getDouble("total_tp_price");
				double doubleDiscountAmount = rs.getDouble("discount_amt");
				double doubleTotalAmount = rs.getDouble("total_amount");
				String strFromAccount = rs.getString("from_account_id");
				String strToAccount = rs.getString("to_account_id");
				
				p.setPurchase_id(strPurchase);
				p.setRequisition_id(strRequisition);
				p.setProduct_id(strProduct);
				p.setBonus_id(strBonus);
				p.setOrder_status(strOrderStatus);
				p.setDelivery_status(strDeliveryStatus);
				p.setOrder_quantity(intOrderQuantity);
				p.setTp_price(doubleTpPrice);
				p.setTotal_tp_price(doubleTotalTpPrice);
				p.setDiscount_amt(doubleDiscountAmount);
				p.setTotal_amount(doubleTotalAmount);
				p.setFrom_account_id(strFromAccount);
				p.setTo_account_id(strToAccount);
				
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
		
		return p;
	}
	// selected other respective id during update [E]

}
