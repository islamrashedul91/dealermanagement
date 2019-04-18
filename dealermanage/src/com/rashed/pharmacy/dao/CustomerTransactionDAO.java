package com.rashed.pharmacy.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.rashed.pharmacy.model.Product;
import com.rashed.pharmacy.model.Requisition;
import com.rashed.pharmacy.model.CustomerTransaction;
import com.rashed.pharmacy.dao.SalesDAO;
import com.rashed.pharmacy.util.*;

public class CustomerTransactionDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	private SalesDAO sdao;
	
	public CustomerTransactionDAO(){
		//con  = DbUtil.getConnection();
		sdao = new SalesDAO();
	}
	
	
	public void save(CustomerTransaction ct){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO customer_transaction(transaction_id, transaction_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO customer_transaction(transaction_id, transaction_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			ps.setString(1, ct.getTransaction_id());
			ps.setString(2, ct.getTransaction_type());
			ps.setString(3, ct.getRequisition_id());
			ps.setString(4, ct.getCustomer_id());
			ps.setString(5, ct.getCustomer_name());
			ps.setString(6, ct.getMobile());
			ps.setString(7, ct.getProduct_id());
			ps.setString(8, ct.getProduct_name());
			ps.setString(9, ct.getPack_type());
			ps.setString(10, ct.getPack_size());
			ps.setInt(11, ct.getPiceces());
			ps.setString(12, ct.getBonus_id());
			ps.setString(13, ct.getBonus_name());
			ps.setString(14, ct.getOrder_pack());
			ps.setInt(15, ct.getOrder_quantity());
			ps.setDouble(16, ct.getMrp_price());
			ps.setDouble(17, ct.getTotal_mrp_price());
			ps.setDouble(18, ct.getDiscount_amt());
			ps.setDouble(19, ct.getTotal_amount());
			ps.setString(20, ct.getNeeded_date_time());
			ps.setString(21, ct.getFrom_account_id());
			ps.setString(22, ct.getTo_account_id());
			ps.setString(23, ct.getSalesman_id());
			ps.setString(24, ct.getOrder_status());
			ps.setString(25, ct.getDelivery_status());
			ps.setString(26, ct.getCreated());
			ps.setString(27, ct.getUpdated());
			ps.setString(28, ct.getCreated_by());
			ps.setString(29, ct.getUpdated_by());
			
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
	
	public void delete(String transaction_id){
		try{
			//PreparedStatement ps = con.prepareStatement("DELETE FROM customer_transaction WHERE transaction_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM customer_transaction WHERE transaction_id=?");
			
			ps.setString(1, transaction_id);
			
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
	
	public void update(CustomerTransaction ct){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE customer_transaction set transaction_type=?, requisition_id=?, customer_id=?, customer_name=?, mobile=?, product_id=?, product_name=?, pack_type=?, pack_size=?, piceces=?, bonus_id=?, bonus_name=?, order_pack=?, order_quantity=?, mrp_price=?, total_mrp_price=?, discount_amt=?, total_amount=?, needed_date_time=?, from_account_id=?, to_account_id=?, salesman_id=?, order_status=?, delivery_status=?, created=?, updated=?, created_by=?, updated_by=? where transaction_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE customer_transaction set transaction_type=?, requisition_id=?, customer_id=?, customer_name=?, mobile=?, product_id=?, product_name=?, pack_type=?, pack_size=?, piceces=?, bonus_id=?, bonus_name=?, order_pack=?, order_quantity=?, mrp_price=?, total_mrp_price=?, discount_amt=?, total_amount=?, needed_date_time=?, from_account_id=?, to_account_id=?, salesman_id=?, order_status=?, delivery_status=?, created=?, updated=?, created_by=?, updated_by=? where transaction_id=?");
			
			ps.setString(1, ct.getTransaction_type());
			ps.setString(2, ct.getRequisition_id());
			ps.setString(3, ct.getCustomer_id());
			ps.setString(4, ct.getCustomer_name());
			ps.setString(5, ct.getMobile());
			ps.setString(6, ct.getProduct_id());
			ps.setString(7, ct.getProduct_name());
			ps.setString(8, ct.getPack_type());
			ps.setString(9, ct.getPack_size());
			ps.setInt(10, ct.getPiceces());
			ps.setString(11, ct.getBonus_id());
			ps.setString(12, ct.getBonus_name());
			ps.setString(13, ct.getOrder_pack());
			ps.setInt(14, ct.getOrder_quantity());
			ps.setDouble(15, ct.getMrp_price());
			ps.setDouble(16, ct.getTotal_mrp_price());
			ps.setDouble(17, ct.getDiscount_amt());
			ps.setDouble(18, ct.getTotal_amount());
			ps.setString(19, ct.getNeeded_date_time());
			ps.setString(20, ct.getFrom_account_id());
			ps.setString(21, ct.getTo_account_id());
			ps.setString(22, ct.getSalesman_id());
			ps.setString(23, ct.getOrder_status());
			ps.setString(24, ct.getDelivery_status());
			ps.setString(25, ct.getCreated());
			ps.setString(26, ct.getUpdated());
			ps.setString(27, ct.getCreated_by());
			ps.setString(28, ct.getUpdated_by());
			ps.setString(29, ct.getTransaction_id());
			
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
	
	public List<CustomerTransaction> getAllCustomerTransaction(){
		List<CustomerTransaction> list = new ArrayList<CustomerTransaction>();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT transaction_id, transaction_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by FROM customer_transaction ORDER BY transaction_id DESC");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_id, transaction_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by FROM customer_transaction ORDER BY transaction_id DESC");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				CustomerTransaction ct = new CustomerTransaction();				
				
				ct.setTransaction_id(rs.getString(1));
				ct.setTransaction_type(rs.getString(2));
				ct.setRequisition_id(rs.getString(3));
				ct.setCustomer_id(rs.getString(4));
				ct.setCustomer_name(rs.getString(5));
				ct.setMobile(rs.getString(6));
				ct.setProduct_id(rs.getString(7));
				ct.setProduct_name(rs.getString(8));
				ct.setPack_type(rs.getString(9));
				ct.setPack_size(rs.getString(10));
				ct.setPiceces(rs.getInt(11));
				ct.setBonus_id(rs.getString(12));
				ct.setBonus_name(rs.getString(13));
				ct.setOrder_pack(rs.getString(14));
				ct.setOrder_quantity(rs.getInt(15));
				ct.setMrp_price(rs.getDouble(16));
				ct.setTotal_mrp_price(rs.getDouble(17));
				ct.setDiscount_amt(rs.getDouble(18));
				ct.setTotal_amount(rs.getDouble(19));
				ct.setNeeded_date_time(rs.getString(20));
				ct.setFrom_account_id(rs.getString(21));
				ct.setTo_account_id(rs.getString(22));
				ct.setSalesman_id(rs.getString(23));
				ct.setOrder_status(rs.getString(24));
				ct.setDelivery_status(rs.getString(25));
				ct.setCreated(rs.getString(26));
				ct.setUpdated(rs.getString(27));
				ct.setCreated_by(rs.getString(28));
				ct.setUpdated_by(rs.getString(29));
			
				list.add(ct);				
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
	
	public CustomerTransaction getCustomerTransactionById(String transaction_id){
		CustomerTransaction ct = new CustomerTransaction();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT transaction_id, transaction_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by FROM customer_transaction where transaction_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_id, transaction_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by FROM customer_transaction where transaction_id=?");
			
			ps.setString(1, transaction_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				ct.setTransaction_id(rs.getString(1));
				ct.setTransaction_type(rs.getString(2));
				ct.setRequisition_id(rs.getString(3));
				ct.setCustomer_id(rs.getString(4));
				ct.setCustomer_name(rs.getString(5));
				ct.setMobile(rs.getString(6));
				ct.setProduct_id(rs.getString(7));
				ct.setProduct_name(rs.getString(8));
				ct.setPack_type(rs.getString(9));
				ct.setPack_size(rs.getString(10));
				ct.setPiceces(rs.getInt(11));
				ct.setBonus_id(rs.getString(12));
				ct.setBonus_name(rs.getString(13));
				ct.setOrder_pack(rs.getString(14));
				ct.setOrder_quantity(rs.getInt(15));
				ct.setMrp_price(rs.getDouble(16));
				ct.setTotal_mrp_price(rs.getDouble(17));
				ct.setDiscount_amt(rs.getDouble(18));
				ct.setTotal_amount(rs.getDouble(19));
				ct.setNeeded_date_time(rs.getString(20));
				ct.setFrom_account_id(rs.getString(21));
				ct.setTo_account_id(rs.getString(22));
				ct.setSalesman_id(rs.getString(23));
				ct.setOrder_status(rs.getString(24));
				ct.setDelivery_status(rs.getString(25));
				ct.setCreated(rs.getString(26));
				ct.setUpdated(rs.getString(27));
				ct.setCreated_by(rs.getString(28));
				ct.setUpdated_by(rs.getString(29));
				
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

		return ct;
	}
	
	// generated auto increment id during add [S]
	public CustomerTransaction getCustomerTransactionID(){
		CustomerTransaction ct = new CustomerTransaction();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT transaction_id FROM customer_transaction");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_id FROM customer_transaction");
			rs = ps.executeQuery();
			
			int transaction_id = 0;
			
			if(rs.next() == false) {
				transaction_id = 1000000000;
				transaction_id = transaction_id+1;
				ct.setTransaction_id("TRNX" + String.valueOf(transaction_id));
			} else {
				if(rs.last()) {
					String strTransaction = rs.getString("transaction_id");
					transaction_id = Integer.parseInt(strTransaction.replaceAll("[^0-9]", ""));
					transaction_id = transaction_id+1;
					ct.setTransaction_id("TRNX" + String.valueOf(transaction_id));
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
		
		return ct;
	}
	// generated auto increment id during add [E]
	
	// selected other respective id during update [S]
	public CustomerTransaction getSelectedOtherID(String transaction_id){
		CustomerTransaction ct = new CustomerTransaction();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT transaction_id, requisition_id, customer_id, product_id, bonus_id, salesman_id FROM customer_transaction WHERE transaction_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_id, requisition_id, customer_id, product_id, bonus_id, salesman_id FROM customer_transaction WHERE transaction_id=?");
			
			ps.setString(1, transaction_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strTransaction = rs.getString("transaction_id");
				String strRequisition = rs.getString("requisition_id");
				String strCustomer = rs.getString("customer_id");
				String strProduct = rs.getString("product_id");
				String strBonus = rs.getString("bonus_id");
				String strSalesman = rs.getString("salesman_id");
				
				ct.setTransaction_id(strTransaction);
				ct.setRequisition_id(strRequisition);
				ct.setCustomer_id(strCustomer);
				ct.setProduct_id(strProduct);
				ct.setBonus_id(strBonus);
				ct.setSalesman_id(strSalesman);
				
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
		
		return ct;
	}
	// selected other respective id during update [E]
	
	// after Delivery Approve record copy from sales to customerPurchase [S]
	public void salesToCustomerTransaction(String sales_id, String action){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO customer_transaction(transaction_id, transaction_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO customer_transaction(transaction_id, transaction_type, requisition_id, customer_id, customer_name, mobile, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, needed_date_time, from_account_id, to_account_id, salesman_id, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			// generated auto increment id during insertion [S]
			CustomerTransactionDAO ctd = new CustomerTransactionDAO();
			ps.setString(1, ctd.getCustomerTransactionID().getTransaction_id());
			// generated auto increment id during insertion [E]
			//ps.setString(2, "Requisition");
			if(action.equalsIgnoreCase("deliveryReturn")){
				ps.setString(2, "Requisition");
			} else if(action.equalsIgnoreCase("deliveryApprove")){
				ps.setString(2, "Purchase");
			} else if(action.equalsIgnoreCase("cancel")){
				ps.setString(2, "Requisition");
			}
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
