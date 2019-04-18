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
import com.rashed.pharmacy.model.CustomerTransactionMain;
import com.rashed.pharmacy.dao.SalesProductDAO;
import com.rashed.pharmacy.dao.SalesMainDAO;
import com.rashed.pharmacy.util.*;

public class CustomerTransactionMainDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	private SalesProductDAO spdao;
	private SalesMainDAO smmdao;
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public CustomerTransactionMainDAO(){
		//con  = DbUtil.getConnection();
		smmdao = new SalesMainDAO();
		spdao = new SalesProductDAO();
	}
	
	//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
	Date date = new Date();  
	String strDate = formatter.format(date);
	
	public void delete(String transaction_id){
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM customer_transaction_main WHERE transaction_id=?");
			
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
	
	public List<CustomerTransactionMain> getAllCustomerTransactionMain(){
		List<CustomerTransactionMain> list = new ArrayList<CustomerTransactionMain>();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_id, transaction_type, requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated, created_by, updated_by, reason FROM customer_transaction_main ORDER BY created DESC");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				CustomerTransactionMain ctm = new CustomerTransactionMain();				
				
				ctm.setTransaction_id(rs.getString(1));
				ctm.setTransaction_type(rs.getString(2));
				ctm.setRequisition_id(rs.getString(3));
				ctm.setDate_time(rs.getString(4));
				ctm.setCustomer_id(rs.getString(5));
				ctm.setCustomer_name(rs.getString(6));
				ctm.setMobile(rs.getString(7));
				ctm.setNeeded_date_time(rs.getString(8));
				ctm.setFrom_account_id(rs.getString(9));
				ctm.setTo_account_id(rs.getString(10));
				ctm.setSalesman_id(rs.getString(11));
				ctm.setTotal_amount(rs.getDouble(12));
				ctm.setOrder_status(rs.getString(13));
				ctm.setDelivery_status(rs.getString(14));
				ctm.setCreated(rs.getString(15));
				ctm.setUpdated(rs.getString(16));
				ctm.setCreated_by(rs.getString(17));
				ctm.setUpdated_by(rs.getString(18));
				ctm.setReason(rs.getString(19));
			
				list.add(ctm);				
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
	
	public CustomerTransactionMain getCustomerTransactionMainById(String transaction_id){
		CustomerTransactionMain ctm = new CustomerTransactionMain();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_id, transaction_type, requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated, created_by, updated_by, reason FROM customer_transaction_main where transaction_id=?");
			
			ps.setString(1, transaction_id);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				ctm.setTransaction_id(rs.getString(1));
				ctm.setTransaction_type(rs.getString(2));
				ctm.setRequisition_id(rs.getString(3));
				ctm.setDate_time(rs.getString(4));
				ctm.setCustomer_id(rs.getString(5));
				ctm.setCustomer_name(rs.getString(6));
				ctm.setMobile(rs.getString(7));
				ctm.setNeeded_date_time(rs.getString(8));
				ctm.setFrom_account_id(rs.getString(9));
				ctm.setTo_account_id(rs.getString(10));
				ctm.setSalesman_id(rs.getString(11));
				ctm.setTotal_amount(rs.getDouble(12));
				ctm.setOrder_status(rs.getString(13));
				ctm.setDelivery_status(rs.getString(14));
				ctm.setCreated(rs.getString(15));
				ctm.setUpdated(rs.getString(16));
				ctm.setCreated_by(rs.getString(17));
				ctm.setUpdated_by(rs.getString(18));
				ctm.setReason(rs.getString(19));
				
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

		return ctm;
	}
	
	public CustomerTransactionMain getCustomerTransactionMainByIdDateTime(String requisition_id, String date_time){
		CustomerTransactionMain ctm = new CustomerTransactionMain();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_id, transaction_type, requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated, created_by, updated_by, reason FROM customer_transaction_main where requisition_id=? and date_time=?");
			
			ps.setString(1, requisition_id);
			ps.setString(2, date_time);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				ctm.setTransaction_id(rs.getString(1));
				ctm.setTransaction_type(rs.getString(2));
				ctm.setRequisition_id(rs.getString(3));
				ctm.setDate_time(rs.getString(4));
				ctm.setCustomer_id(rs.getString(5));
				ctm.setCustomer_name(rs.getString(6));
				ctm.setMobile(rs.getString(7));
				ctm.setNeeded_date_time(rs.getString(8));
				ctm.setFrom_account_id(rs.getString(9));
				ctm.setTo_account_id(rs.getString(10));
				ctm.setSalesman_id(rs.getString(11));
				ctm.setTotal_amount(rs.getDouble(12));
				ctm.setOrder_status(rs.getString(13));
				ctm.setDelivery_status(rs.getString(14));
				ctm.setCreated(rs.getString(15));
				ctm.setUpdated(rs.getString(16));
				ctm.setCreated_by(rs.getString(17));
				ctm.setUpdated_by(rs.getString(18));
				ctm.setReason(rs.getString(19));
				
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

		return ctm;
	}
	
	// generated auto increment id during add [S]
	public CustomerTransactionMain getCustomerTransactionMainID(){
		CustomerTransactionMain ctm = new CustomerTransactionMain();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_id FROM customer_transaction_main");
			
			rs = ps.executeQuery();
			
			int transaction_id = 0;
			
			if(rs.next() == false) {
				transaction_id = 1000000000;
				transaction_id = transaction_id+1;
				ctm.setTransaction_id("TRNX" + String.valueOf(transaction_id));
			} else {
				if(rs.last()) {
					String strCustomerTransactionMain = rs.getString("transaction_id");
					transaction_id = Integer.parseInt(strCustomerTransactionMain.replaceAll("[^0-9]", ""));
					transaction_id = transaction_id+1;
					ctm.setTransaction_id("TRNX" + String.valueOf(transaction_id));
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
		
		return ctm;
	}
	// generated auto increment id during add [E]
	
	// selected other respective id during update [S]
	public CustomerTransactionMain getSelectedOtherID(String transaction_id){
		CustomerTransactionMain ctm = new CustomerTransactionMain();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT transaction_id, requisition_id, date_time, customer_id, salesman_id, order_status, delivery_status, total_amount FROM customer_transaction_main WHERE transaction_id=?");
			
			ps.setString(1, transaction_id);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strCustomerTransactionMain = rs.getString("transaction_id");
				String strRequisition = rs.getString("requisition_id");
				String strDateTime = rs.getString("date_time");
				String strCustomer = rs.getString("customer_id");
				String strSalesman = rs.getString("salesman_id");
				double dubleTotalAmount = rs.getDouble("total_amount");
				String strOrderStatus = rs.getString("order_status");
				String strDeliveryStatus = rs.getString("delivery_status");
				
				ctm.setTransaction_id(strCustomerTransactionMain);
				ctm.setRequisition_id(strRequisition);
				ctm.setDate_time(strDateTime);
				ctm.setCustomer_id(strCustomer);
				ctm.setSalesman_id(strSalesman);
				ctm.setTotal_amount(dubleTotalAmount);
				ctm.setOrder_status(strOrderStatus);
				ctm.setDelivery_status(strDeliveryStatus);
				
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
		
		return ctm;
	}
	// selected other respective id during update [E]
	
	// after cancel/deliveryReturn record copy from sales to transaction [S]
	public void salesMainToCustomerTransactionMain(String requisition_id, String date_time){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO customer_transaction_main(transaction_id, transaction_type, requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated, created_by, updated_by, reason) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			// generated auto increment id during insertion [S]
			//ps.setString(1, "1000000001");
			CustomerTransactionMainDAO ctmdao = new CustomerTransactionMainDAO();
			ps.setString(1, ctmdao.getCustomerTransactionMainID().getTransaction_id());
			// generated auto increment id during insertion [E]
			ps.setString(2, "Purchase");
			ps.setString(3, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getRequisition_id());
			ps.setString(4, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getDate_time());
			ps.setString(5, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getCustomer_id());
			ps.setString(6, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getCustomer_name());
			ps.setString(7, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getMobile());
			ps.setString(8, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getNeeded_date_time());
			ps.setString(9, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getFrom_account_id());
			ps.setString(10, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getTo_account_id());
			ps.setString(11, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getSalesman_id());
			ps.setDouble(12, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getTotal_amount());
			ps.setString(13, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getOrder_status());
			ps.setString(14, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getDelivery_status());
			ps.setString(15, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getCreated());
			ps.setString(16, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getUpdated());
			ps.setString(17, "");
			ps.setString(18, "");
			ps.setString(19, "");
			
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
	
	public void returnTotalAmount(String requisition_id, String date_time){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE customer_transaction_main set total_amount=?, updated=? where requisition_id=? and date_time=?");
			
			CustomerTransactionMainDAO ctmdao = new CustomerTransactionMainDAO();
			
			//ps.setDouble(1, spdao.sumTotalAmountBasedOnReturnStatus(requisition_id, date_time).getTotal_amount());
			ps.setDouble(1, (ctmdao.getCustomerTransactionMainByIdDateTime(requisition_id, date_time).getTotal_amount() + spdao.sumTotalAmountBasedOnReturnStatus(requisition_id, date_time).getTotal_amount()));
			ps.setString(2, strDate);
			ps.setString(3, requisition_id);
			ps.setString(4, date_time);
			
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
	// after cancel/deliveryReturn record copy from sales to transaction [E]
	
	// from sales product screen after cancel/deliveryReturn record copy from sales to transaction [ES
	public void productSalesMainToCustomerTransactionMain(String requisition_id, String date_time){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO customer_transaction_main(transaction_id, transaction_type, requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated, created_by, updated_by, reason) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			// generated auto increment id during insertion [S]
			//ps.setString(1, "1000000001");
			CustomerTransactionMainDAO ctmdao = new CustomerTransactionMainDAO();
			ps.setString(1, ctmdao.getCustomerTransactionMainID().getTransaction_id());
			// generated auto increment id during insertion [E]
			ps.setString(2, "Purchase");
			ps.setString(3, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getRequisition_id());
			ps.setString(4, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getDate_time());
			ps.setString(5, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getCustomer_id());
			ps.setString(6, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getCustomer_name());
			ps.setString(7, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getMobile());
			ps.setString(8, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getNeeded_date_time());
			ps.setString(9, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getFrom_account_id());
			ps.setString(10, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getTo_account_id());
			ps.setString(11, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getSalesman_id());
			//ps.setDouble(12, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getTotal_amount());
			//ps.setDouble(12, smmdao.sumTotalAmountBasedOnReturnStatus(requisition_id, date_time, "R"));
			ps.setDouble(12, spdao.sumTotalAmountBasedOnReturnStatus(requisition_id, date_time).getTotal_amount());
			ps.setString(13, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getOrder_status());
			//ps.setString(14, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getDelivery_status());
			ps.setString(14, "R");
			ps.setString(15, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getCreated());
			ps.setString(16, smmdao.getSalesMainByIdDateTime(requisition_id, date_time).getUpdated());
			ps.setString(17, "");
			ps.setString(18, "");
			ps.setString(19, "");
			
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
	// from sales product screen after cancel/deliveryReturn record copy from sales to transaction [E]

}
