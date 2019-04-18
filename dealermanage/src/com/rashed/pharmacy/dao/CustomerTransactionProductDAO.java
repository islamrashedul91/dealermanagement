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
import com.rashed.pharmacy.model.SalesProduct;
import com.rashed.pharmacy.model.CustomerTransactionProduct;
import com.rashed.pharmacy.util.*;

public class CustomerTransactionProductDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public CustomerTransactionProductDAO(){
		//con  = DbUtil.getConnection();
	}
	
	//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
	Date date = new Date();  
	String strDate = formatter.format(date);
	
	public void delete(String transaction_product_id){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM customer_transaction_product WHERE transaction_product_id=?");
			
			ps.setString(1, transaction_product_id);
			
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
	
	public List<CustomerTransactionProduct> getAllCustomerTransactionProduct(){
		List<CustomerTransactionProduct> list = new ArrayList<CustomerTransactionProduct>();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_product_id, transaction_id, transaction_type, requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by, reason FROM customer_transaction_product ORDER BY created DESC");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				CustomerTransactionProduct ctp = new CustomerTransactionProduct();				
				
				ctp.setTransaction_product_id(rs.getString(1));
				ctp.setTransaction_id(rs.getString(2));
				ctp.setTransaction_type(rs.getString(3));
				ctp.setRequisition_product_id(rs.getString(4));
				ctp.setRequisition_id(rs.getString(5));
				ctp.setDate_time(rs.getString(6));
				ctp.setProduct_id(rs.getString(7));
				ctp.setProduct_name(rs.getString(8));
				ctp.setPack_type(rs.getString(9));
				ctp.setPack_size(rs.getString(10));
				ctp.setPiceces(rs.getInt(11));
				ctp.setBonus_id(rs.getString(12));
				ctp.setBonus_name(rs.getString(13));
				ctp.setOrder_pack(rs.getString(14));
				ctp.setOrder_quantity(rs.getInt(15));
				ctp.setMrp_price(rs.getDouble(16));
				ctp.setTotal_mrp_price(rs.getDouble(17));
				ctp.setDiscount_amt(rs.getDouble(18));
				ctp.setTotal_amount(rs.getDouble(19));
				ctp.setOrder_status(rs.getString(20));
				ctp.setDelivery_status(rs.getString(21));
				ctp.setCreated(rs.getString(22));
				ctp.setUpdated(rs.getString(23));
				ctp.setCreated_by(rs.getString(24));
				ctp.setUpdated_by(rs.getString(25));
				ctp.setReason(rs.getString(26));
			
				list.add(ctp);				
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
	
	public CustomerTransactionProduct getCustomerTransactionProductById(String transaction_product_id){
		CustomerTransactionProduct ctp = new CustomerTransactionProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_product_id, transaction_id, transaction_type, requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by, reason FROM customer_transaction_product where transaction_product_id=?");
			
			ps.setString(1, transaction_product_id);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				ctp.setTransaction_product_id(rs.getString(1));
				ctp.setTransaction_id(rs.getString(2));
				ctp.setTransaction_type(rs.getString(3));
				ctp.setRequisition_product_id(rs.getString(4));
				ctp.setRequisition_id(rs.getString(5));
				ctp.setDate_time(rs.getString(6));
				ctp.setProduct_id(rs.getString(7));
				ctp.setProduct_name(rs.getString(8));
				ctp.setPack_type(rs.getString(9));
				ctp.setPack_size(rs.getString(10));
				ctp.setPiceces(rs.getInt(11));
				ctp.setBonus_id(rs.getString(12));
				ctp.setBonus_name(rs.getString(13));
				ctp.setOrder_pack(rs.getString(14));
				ctp.setOrder_quantity(rs.getInt(15));
				ctp.setMrp_price(rs.getDouble(16));
				ctp.setTotal_mrp_price(rs.getDouble(17));
				ctp.setDiscount_amt(rs.getDouble(18));
				ctp.setTotal_amount(rs.getDouble(19));
				ctp.setOrder_status(rs.getString(20));
				ctp.setDelivery_status(rs.getString(21));
				ctp.setCreated(rs.getString(22));
				ctp.setUpdated(rs.getString(23));
				ctp.setCreated_by(rs.getString(24));
				ctp.setUpdated_by(rs.getString(25));
				ctp.setReason(rs.getString(26));
				
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

		return ctp;
	}
	
	// generated auto increment id during add [S]
	public CustomerTransactionProduct getCustomerTransactionProductID(){
		CustomerTransactionProduct ctp = new CustomerTransactionProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_product_id FROM customer_transaction_product");
			
			rs = ps.executeQuery();
			
			int transaction_product_id = 0;
			
			if(rs.next() == false) {
				transaction_product_id = 1000000000;
				transaction_product_id = transaction_product_id+1;
				ctp.setTransaction_product_id("TPDT" + String.valueOf(transaction_product_id));
			} else {
				if(rs.last()) {
					String strTransactionProduct = rs.getString("transaction_product_id");
					transaction_product_id = Integer.parseInt(strTransactionProduct.replaceAll("[^0-9]", ""));
					transaction_product_id = transaction_product_id+1;
					ctp.setTransaction_product_id("TPDT" + String.valueOf(transaction_product_id));
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
		
		return ctp;
	}
	// generated auto increment id during add [E]
	
	// selected other respective id during update [S]
	public CustomerTransactionProduct getSelectedOtherID(String transaction_product_id){
		CustomerTransactionProduct ctp = new CustomerTransactionProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_product_id, purchase_id, requisition_product_id, requisition_id, product_id, bonus_id, order_status, order_quantity FROM customer_transaction_product WHERE transaction_product_id=?");
			
			ps.setString(1, transaction_product_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strTransactionProduct = rs.getString("transaction_product_id");
				String strTransactionMain = rs.getString("transaction_id");
				String strRequisitionProduct = rs.getString("requisition_product_id");
				String strRequisition = rs.getString("requisition_id");
				String strProduct = rs.getString("product_id");
				String strBonus = rs.getString("bonus_id");
				String strOrderStatus = rs.getString("order_status");
				int intOrderQuantity = rs.getInt("order_quantity");
				
				ctp.setTransaction_product_id(strTransactionProduct);
				ctp.setTransaction_id(strTransactionMain);
				ctp.setRequisition_id(strRequisition);
				ctp.setProduct_id(strProduct);
				ctp.setBonus_id(strBonus);
				ctp.setOrder_status(strOrderStatus);
				ctp.setOrder_quantity(intOrderQuantity);
				
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
		
		return ctp;
	}
	// selected other respective id during update [E]
	
	public List<CustomerTransactionProduct> getAllCustomerTransactionProductByMainIdDateTime(String transaction_id, String requisition_id, String strDateTime){
		List<CustomerTransactionProduct> list = new ArrayList<CustomerTransactionProduct>();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_product_id, transaction_id, transaction_type, requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by, reason FROM customer_transaction_product where transaction_id=? and requisition_id=? and date_time=?");
			
			ps.setString(1, transaction_id);
			ps.setString(2, requisition_id);
			ps.setString(3, strDateTime);
			
			rs = ps.executeQuery();
			
			while (rs.next()) {
				CustomerTransactionProduct ctp = new CustomerTransactionProduct();				
				
				ctp.setTransaction_product_id(rs.getString(1));
				ctp.setTransaction_id(rs.getString(2));
				ctp.setTransaction_type(rs.getString(3));
				ctp.setRequisition_product_id(rs.getString(4));
				ctp.setRequisition_id(rs.getString(5));
				ctp.setDate_time(rs.getString(6));
				ctp.setProduct_id(rs.getString(7));
				ctp.setProduct_name(rs.getString(8));
				ctp.setPack_type(rs.getString(9));
				ctp.setPack_size(rs.getString(10));
				ctp.setPiceces(rs.getInt(11));
				ctp.setBonus_id(rs.getString(12));
				ctp.setBonus_name(rs.getString(13));
				ctp.setOrder_pack(rs.getString(14));
				ctp.setOrder_quantity(rs.getInt(15));
				ctp.setMrp_price(rs.getDouble(16));
				ctp.setTotal_mrp_price(rs.getDouble(17));
				ctp.setDiscount_amt(rs.getDouble(18));
				ctp.setTotal_amount(rs.getDouble(19));
				ctp.setOrder_status(rs.getString(20));
				ctp.setDelivery_status(rs.getString(21));
				ctp.setCreated(rs.getString(22));
				ctp.setUpdated(rs.getString(23));
				ctp.setCreated_by(rs.getString(24));
				ctp.setUpdated_by(rs.getString(25));
			
				list.add(ctp);				
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
	
	// for Requisition Product sum total amount [S]
	public CustomerTransactionProduct sumTotalAmount(String transaction_id, String requisition_id, String date_time){
		CustomerTransactionProduct ctp = new CustomerTransactionProduct();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sum(total_amount) FROM customer_transaction_product where transaction_id=? and requisition_id=? and date_time=?");
			
			ps.setString(1, transaction_id);
			ps.setString(2, requisition_id);
			ps.setString(3, date_time);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if (rs.next()) {
				ctp.setTotal_amount(rs.getDouble(1));
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
		
		return ctp;
	}
	// for Requisition Product sum total amount [E]
	
	// after cancel/delivery  return insert into customer_transaction_product one by one from a list based on sales_product id and date time [E]
	public void SalesProductToCustomerTransactionProduct(String strType, String strRequisitionProductId, String strRequisitionId, String strDateTime, String strProductId,
												String strProductName, String strPackType,String strPackSize, int intPieces, String strBonusId,
												String strBonusName, String strOrderPack, int intOrderQuantity, double doubleMrp, double doubleTotalMrp,
												double doubleDiscount, double doubleTotalAmount, String strOrderStatus, String strDeliveryStatus,
												String strCreated, String strUpdated){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO customer_transaction_product(transaction_product_id, transaction_id, transaction_type, requisition_product_id, requisition_id, date_time, product_id, product_name, pack_type, pack_size, piceces, bonus_id, bonus_name, order_pack, order_quantity, mrp_price, total_mrp_price, discount_amt, total_amount, order_status, delivery_status, created, updated, created_by, updated_by, reason) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			CustomerTransactionMainDAO ctmdao = new CustomerTransactionMainDAO();
			
			CustomerTransactionProductDAO ctpdao = new CustomerTransactionProductDAO();
			
			ps.setString(1, ctpdao.getCustomerTransactionProductID().getTransaction_product_id());
			ps.setString(2, ctmdao.getCustomerTransactionMainByIdDateTime(strRequisitionId, strDateTime).getTransaction_id());
			ps.setString(3, "Purchase");
			//ps.setString(3, strType);
			ps.setString(4, strRequisitionProductId);
			ps.setString(5, strRequisitionId);
			ps.setString(6, strDateTime);
			ps.setString(7, strProductId);
			ps.setString(8, strProductName);
			ps.setString(9, strPackType);
			ps.setString(10, strPackSize);
			ps.setInt(11, intPieces);
			ps.setString(12, strBonusId);
			ps.setString(13, strBonusName);
			ps.setString(14, strOrderPack);
			ps.setInt(15, intOrderQuantity);
			ps.setDouble(16, doubleMrp);
			ps.setDouble(17, doubleTotalMrp);
			ps.setDouble(18, doubleDiscount);
			ps.setDouble(19, doubleTotalAmount);
			ps.setString(20, strOrderStatus);
			ps.setString(21, strDeliveryStatus);
			ps.setString(22, strCreated);
			ps.setString(23, strUpdated);
			ps.setString(24, "");
			ps.setString(25, "");
			ps.setString(26, "");
			
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
	// after cancel/delivery return insert into customer_transaction_product one by one from a list based on sales_product id and date time [E]
	
}