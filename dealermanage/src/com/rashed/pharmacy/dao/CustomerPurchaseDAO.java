package com.rashed.pharmacy.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.rashed.pharmacy.model.Product;
import com.rashed.pharmacy.model.Requisition;
import com.rashed.pharmacy.model.CustomerPurchase;
import com.rashed.pharmacy.dao.SalesDAO;
import com.rashed.pharmacy.util.*;

public class CustomerPurchaseDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	private SalesDAO sdao;
	
	public CustomerPurchaseDAO(){
		//con  = DbUtil.getConnection();
		sdao = new SalesDAO();
	}
	
	
	public void save(CustomerPurchase cp){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO customer_purchase(purchase_id, purchase_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO customer_purchase(purchase_id, purchase_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			ps.setString(1, cp.getPurchase_id());
			ps.setString(2, cp.getPurchase_type());
			ps.setString(3, cp.getRequisition_id());
			ps.setString(4, cp.getCustomer_id());
			ps.setString(5, cp.getCustomer_name());
			ps.setString(6, cp.getMobile());
			ps.setString(7, cp.getProduct_id());
			ps.setString(8, cp.getProduct_name());
			ps.setString(9, cp.getPack_type());
			ps.setString(10, cp.getPack_size());
			ps.setInt(11, cp.getPiceces());
			ps.setString(12, cp.getBonus_id());
			ps.setString(13, cp.getBonus_name());
			ps.setString(14, cp.getOrder_pack());
			ps.setInt(15, cp.getOrder_quantity());
			ps.setDouble(16, cp.getMrp_price());
			ps.setDouble(17, cp.getTotal_mrp_price());
			ps.setDouble(18, cp.getDiscount_amt());
			ps.setDouble(19, cp.getTotal_amount());
			ps.setString(20, cp.getNeeded_date_time());
			ps.setString(21, cp.getFrom_account_id());
			ps.setString(22, cp.getTo_account_id());
			ps.setString(23, cp.getSalesman_id());
			ps.setString(24, cp.getOrder_status());
			ps.setString(25, cp.getDelivery_status());
			ps.setString(26, cp.getCreated());
			ps.setString(27, cp.getUpdated());
			ps.setString(28, cp.getCreated_by());
			ps.setString(29, cp.getUpdated_by());
			
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
			//PreparedStatement ps = con.prepareStatement("DELETE FROM customer_purchase WHERE purchase_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM customer_purchase WHERE purchase_id=?");
			
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
	
	public void update(CustomerPurchase cp){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE customer_purchase set purchase_type=?, requisition_id=?, customer_id=?, customer_name=?, mobile=?, product_id=?, product_name=?, pack_type=?, pack_size=?, piceces=?, bonus_id=?, bonus_name=?, order_pack=?, order_quantity=?, mrp_price=?, total_mrp_price=?, discount_amt=?, total_amount=?, needed_date_time=?, from_account_id=?, to_account_id=?, salesman_id=?, order_status=?, delivery_status=?, created=?, updated=?, created_by=?, updated_by=? where purchase_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE customer_purchase set purchase_type=?, requisition_id=?, customer_id=?, customer_name=?, mobile=?, product_id=?, product_name=?, pack_type=?, pack_size=?, piceces=?, bonus_id=?, bonus_name=?, order_pack=?, order_quantity=?, mrp_price=?, total_mrp_price=?, discount_amt=?, total_amount=?, needed_date_time=?, from_account_id=?, to_account_id=?, salesman_id=?, order_status=?, delivery_status=?, created=?, updated=?, created_by=?, updated_by=? where purchase_id=?");
			
			ps.setString(1, cp.getPurchase_type());
			ps.setString(2, cp.getRequisition_id());
			ps.setString(3, cp.getCustomer_id());
			ps.setString(4, cp.getCustomer_name());
			ps.setString(5, cp.getMobile());
			ps.setString(6, cp.getProduct_id());
			ps.setString(7, cp.getProduct_name());
			ps.setString(8, cp.getPack_type());
			ps.setString(9, cp.getPack_size());
			ps.setInt(10, cp.getPiceces());
			ps.setString(11, cp.getBonus_id());
			ps.setString(12, cp.getBonus_name());
			ps.setString(13, cp.getOrder_pack());
			ps.setInt(14, cp.getOrder_quantity());
			ps.setDouble(15, cp.getMrp_price());
			ps.setDouble(16, cp.getTotal_mrp_price());
			ps.setDouble(17, cp.getDiscount_amt());
			ps.setDouble(18, cp.getTotal_amount());
			ps.setString(19, cp.getNeeded_date_time());
			ps.setString(20, cp.getFrom_account_id());
			ps.setString(21, cp.getTo_account_id());
			ps.setString(22, cp.getSalesman_id());
			ps.setString(23, cp.getOrder_status());
			ps.setString(24, cp.getDelivery_status());
			ps.setString(25, cp.getCreated());
			ps.setString(26, cp.getUpdated());
			ps.setString(27, cp.getCreated_by());
			ps.setString(28, cp.getUpdated_by());
			ps.setString(29, cp.getPurchase_id());
			
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
	
	public List<CustomerPurchase> getAllCustomerPurchase(){
		List<CustomerPurchase> list = new ArrayList<CustomerPurchase>();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT purchase_id, purchase_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by FROM customer_purchase ORDER BY purchase_id DESC");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_id, purchase_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by FROM customer_purchase ORDER BY purchase_id DESC");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				CustomerPurchase cp = new CustomerPurchase();				
				
				cp.setPurchase_id(rs.getString(1));
				cp.setPurchase_type(rs.getString(2));
				cp.setRequisition_id(rs.getString(3));
				cp.setCustomer_id(rs.getString(4));
				cp.setCustomer_name(rs.getString(5));
				cp.setMobile(rs.getString(6));
				cp.setProduct_id(rs.getString(7));
				cp.setProduct_name(rs.getString(8));
				cp.setPack_type(rs.getString(9));
				cp.setPack_size(rs.getString(10));
				cp.setPiceces(rs.getInt(11));
				cp.setBonus_id(rs.getString(12));
				cp.setBonus_name(rs.getString(13));
				cp.setOrder_pack(rs.getString(14));
				cp.setOrder_quantity(rs.getInt(15));
				cp.setMrp_price(rs.getDouble(16));
				cp.setTotal_mrp_price(rs.getDouble(17));
				cp.setDiscount_amt(rs.getDouble(18));
				cp.setTotal_amount(rs.getDouble(19));
				cp.setNeeded_date_time(rs.getString(20));
				cp.setFrom_account_id(rs.getString(21));
				cp.setTo_account_id(rs.getString(22));
				cp.setSalesman_id(rs.getString(23));
				cp.setOrder_status(rs.getString(24));
				cp.setDelivery_status(rs.getString(25));
				cp.setCreated(rs.getString(26));
				cp.setUpdated(rs.getString(27));
				cp.setCreated_by(rs.getString(28));
				cp.setUpdated_by(rs.getString(29));
			
				list.add(cp);				
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
	
	public CustomerPurchase getCustomerPurchaseById(String purchase_id){
		CustomerPurchase cp = new CustomerPurchase();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT purchase_id, purchase_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by FROM customer_purchase where purchase_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_id, purchase_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by FROM customer_purchase where purchase_id=?");
			
			ps.setString(1, purchase_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				cp.setPurchase_id(rs.getString(1));
				cp.setPurchase_type(rs.getString(2));
				cp.setRequisition_id(rs.getString(3));
				cp.setCustomer_id(rs.getString(4));
				cp.setCustomer_name(rs.getString(5));
				cp.setMobile(rs.getString(6));
				cp.setProduct_id(rs.getString(7));
				cp.setProduct_name(rs.getString(8));
				cp.setPack_type(rs.getString(9));
				cp.setPack_size(rs.getString(10));
				cp.setPiceces(rs.getInt(11));
				cp.setBonus_id(rs.getString(12));
				cp.setBonus_name(rs.getString(13));
				cp.setOrder_pack(rs.getString(14));
				cp.setOrder_quantity(rs.getInt(15));
				cp.setMrp_price(rs.getDouble(16));
				cp.setTotal_mrp_price(rs.getDouble(17));
				cp.setDiscount_amt(rs.getDouble(18));
				cp.setTotal_amount(rs.getDouble(19));
				cp.setNeeded_date_time(rs.getString(20));
				cp.setFrom_account_id(rs.getString(21));
				cp.setTo_account_id(rs.getString(22));
				cp.setSalesman_id(rs.getString(23));
				cp.setOrder_status(rs.getString(24));
				cp.setDelivery_status(rs.getString(25));
				cp.setCreated(rs.getString(26));
				cp.setUpdated(rs.getString(27));
				cp.setCreated_by(rs.getString(28));
				cp.setUpdated_by(rs.getString(29));
				
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

		return cp;
	}
	
	// generated auto increment id during add [S]
	public CustomerPurchase getCustomerPurchaseID(){
		CustomerPurchase cp = new CustomerPurchase();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT purchase_id FROM customer_purchase");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_id FROM customer_purchase");
			rs = ps.executeQuery();
			
			int purchase_id = 0;
			
			if(rs.next() == false) {
				purchase_id = 1000000000;
				purchase_id = purchase_id+1;
				cp.setPurchase_id("PRCH" + String.valueOf(purchase_id));
			} else {
				if(rs.last()) {
					String strPurchase = rs.getString("purchase_id");
					purchase_id = Integer.parseInt(strPurchase.replaceAll("[^0-9]", ""));
					purchase_id = purchase_id+1;
					cp.setPurchase_id("PRCH" + String.valueOf(purchase_id));
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
		
		return cp;
	}
	// generated auto increment id during add [E]
	
	// selected other respective id during update [S]
	public CustomerPurchase getSelectedOtherID(String purchase_id){
		CustomerPurchase cp = new CustomerPurchase();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT purchase_id, requisition_id, customer_id, product_id, bonus_id, salesman_id FROM customer_purchase WHERE purchase_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_id, requisition_id, customer_id, product_id, bonus_id, salesman_id FROM customer_purchase WHERE purchase_id=?");
			
			ps.setString(1, purchase_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strPurchase = rs.getString("purchase_id");
				String strRequisition = rs.getString("requisition_id");
				String strCustomer = rs.getString("customer_id");
				String strProduct = rs.getString("product_id");
				String strBonus = rs.getString("bonus_id");
				String strSalesman = rs.getString("salesman_id");
				
				cp.setPurchase_id(strPurchase);
				cp.setRequisition_id(strRequisition);
				cp.setCustomer_id(strCustomer);
				cp.setProduct_id(strProduct);
				cp.setBonus_id(strBonus);
				cp.setSalesman_id(strSalesman);
				
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
		
		return cp;
	}
	// selected other respective id during update [E]
	
	// after Delivery Approve record copy from sales to customerPurchase [S]
	public void salesToCustomerPurchase(String sales_id){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO customer_purchase(purchase_id, purchase_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO customer_purchase(purchase_id, purchase_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			// generated auto increment id during insertion [S]
			//ps.setString(1, "1000000001");
			CustomerPurchaseDAO t = new CustomerPurchaseDAO();
			ps.setString(1, t.getCustomerPurchaseID().getPurchase_id());
			// generated auto increment id during insertion [E]
			ps.setString(2, "Requisition");
			ps.setString(3, sdao.getSalesById(sales_id).getRequisition_id());
			ps.setString(4, sdao.getSalesById(sales_id).getCustomer_id());
			ps.setString(5, sdao.getSalesById(sales_id).getCustomer_name());
			ps.setString(6, sdao.getSalesById(sales_id).getMobile());
			ps.setString(7, sdao.getSalesById(sales_id).getProduct_id());
			ps.setString(8, sdao.getSalesById(sales_id).getProduct_name());
			ps.setString(9, sdao.getSalesById(sales_id).getPack_type());
			ps.setString(10, sdao.getSalesById(sales_id).getPack_size());
			ps.setInt(11, sdao.getSalesById(sales_id).getPiceces());
			ps.setString(12, sdao.getSalesById(sales_id).getBonus_id());
			ps.setString(13, sdao.getSalesById(sales_id).getBonus_name());
			ps.setString(14, sdao.getSalesById(sales_id).getOrder_pack());
			ps.setInt(15, sdao.getSalesById(sales_id).getOrder_quantity());
			ps.setDouble(16, sdao.getSalesById(sales_id).getMrp_price());
			ps.setDouble(17, sdao.getSalesById(sales_id).getTotal_mrp_price());
			ps.setDouble(18, sdao.getSalesById(sales_id).getDiscount_amt());
			ps.setDouble(19, sdao.getSalesById(sales_id).getTotal_amount());
			ps.setString(20, sdao.getSalesById(sales_id).getNeeded_date_time());
			ps.setString(21, sdao.getSalesById(sales_id).getFrom_account_id());
			ps.setString(22, sdao.getSalesById(sales_id).getTo_account_id());
			ps.setString(23, sdao.getSalesById(sales_id).getSalesman_id());
			ps.setString(24, sdao.getSalesById(sales_id).getOrder_status());
			ps.setString(25, sdao.getSalesById(sales_id).getDelivery_status());
			ps.setString(26, sdao.getSalesById(sales_id).getCreated());
			ps.setString(27, sdao.getSalesById(sales_id).getUpdated());
			ps.setString(28, "");
			ps.setString(29, "");
			
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
	// after Delivery Approve record copy from sales to customerPurchase [E]

}
