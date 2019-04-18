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
import com.rashed.pharmacy.model.CustomerPurchaseMain;
import com.rashed.pharmacy.model.SalesMain;
import com.rashed.pharmacy.model.RequisitionMulti;
import com.rashed.pharmacy.dao.RequisitionMultiDAO;
import com.rashed.pharmacy.dao.SalesProductDAO;
import com.rashed.pharmacy.dao.SalesMainDAO;
import com.rashed.pharmacy.util.*;

public class CustomerPurchaseMainDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	private SalesProductDAO spdao;
	private SalesMainDAO smmdao;
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public CustomerPurchaseMainDAO(){
		//con  = DbUtil.getConnection();
		smmdao = new SalesMainDAO();
	}
	
	//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
	Date date = new Date();  
	String strDate = formatter.format(date);
	
	public void save(CustomerPurchaseMain cpm){

		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO customer_purchase_main(purchase_id, purchase_type, requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			ps.setString(1, cpm.getPurchase_id());
			ps.setString(2, cpm.getPurchase_type());
			ps.setString(3, cpm.getRequisition_id());
			ps.setString(4, cpm.getDate_time());
			ps.setString(5, cpm.getCustomer_id());
			ps.setString(6, cpm.getCustomer_name());
			ps.setString(7, cpm.getMobile());
			ps.setString(8, cpm.getNeeded_date_time());
			ps.setString(9, cpm.getFrom_account_id());
			ps.setString(10, cpm.getTo_account_id());
			ps.setString(11, cpm.getSalesman_id());
			ps.setDouble(12, cpm.getTotal_amount());
			ps.setString(13, cpm.getOrder_status());
			ps.setString(14, cpm.getDelivery_status());
			ps.setString(15, cpm.getCreated());
			ps.setString(16, cpm.getUpdated());
			ps.setString(17, cpm.getCreated_by());
			ps.setString(18, cpm.getUpdated_by());
			
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
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM customer_purchase_main WHERE purchase_id=?");
			
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
	
	public void update(CustomerPurchaseMain cpm){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE customer_purchase_main set purchase_type=?, requisition_id=?, date_time=?, customer_id=?, customer_name=?, mobile=?, needed_date_time=?, from_account_id=?, to_account_id=?, salesman_id=?, total_amount=?, order_status=?, delivery_status=?, created=?, updated=?, created_by=?, updated_by=? where purchase_id=?");
			
			ps.setString(1, cpm.getPurchase_type());
			ps.setString(2, cpm.getRequisition_id());
			ps.setString(3, cpm.getDate_time());
			ps.setString(4, cpm.getCustomer_id());
			ps.setString(5, cpm.getCustomer_name());
			ps.setString(6, cpm.getMobile());
			ps.setString(7, cpm.getNeeded_date_time());
			ps.setString(8, cpm.getFrom_account_id());
			ps.setString(9, cpm.getTo_account_id());
			ps.setString(10, cpm.getSalesman_id());
			ps.setDouble(11, cpm.getTotal_amount());
			ps.setString(12, cpm.getOrder_status());
			ps.setString(13, cpm.getDelivery_status());
			ps.setString(14, cpm.getCreated());
			ps.setString(15, cpm.getUpdated());
			ps.setString(16, cpm.getCreated_by());
			ps.setString(17, cpm.getUpdated_by());
			ps.setString(18, cpm.getPurchase_id());
			
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
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE customer_purchase_main set order_status=?, updated=? where purchase_id=?");
			
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
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE customer_purchase_main set order_status=?, updated=? where purchase_id=?");
			
			ps.setString(1, "S");
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
	
	public void deliveryApprove(String purchase_id){
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE customer_purchase_main set delivery_status=?, updated=? where purchase_id=?");
			
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
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE customer_purchase_main set delivery_status=?, updated=? where purchase_id=?");
			
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
	
	public List<CustomerPurchaseMain> getAllCustomerPurchaseMain(){
		List<CustomerPurchaseMain> list = new ArrayList<CustomerPurchaseMain>();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_id, purchase_type, requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM customer_purchase_main ORDER BY created DESC");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				CustomerPurchaseMain cpm = new CustomerPurchaseMain();				
				
				cpm.setPurchase_id(rs.getString(1));
				cpm.setPurchase_type(rs.getString(2));
				cpm.setRequisition_id(rs.getString(3));
				cpm.setDate_time(rs.getString(4));
				cpm.setCustomer_id(rs.getString(5));
				cpm.setCustomer_name(rs.getString(6));
				cpm.setMobile(rs.getString(7));
				cpm.setNeeded_date_time(rs.getString(8));
				cpm.setFrom_account_id(rs.getString(9));
				cpm.setTo_account_id(rs.getString(10));
				cpm.setSalesman_id(rs.getString(11));
				cpm.setTotal_amount(rs.getDouble(12));
				cpm.setOrder_status(rs.getString(13));
				cpm.setDelivery_status(rs.getString(14));
				cpm.setCreated(rs.getString(15));
				cpm.setUpdated(rs.getString(16));
				cpm.setCreated_by(rs.getString(17));
				cpm.setUpdated_by(rs.getString(18));
			
				list.add(cpm);				
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
	
	public CustomerPurchaseMain getCustomerPurchaseMainById(String purchase_id){
		CustomerPurchaseMain cpm = new CustomerPurchaseMain();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_id, purchase_type, requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM customer_purchase_main where purchase_id=?");
			
			ps.setString(1, purchase_id);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				cpm.setPurchase_id(rs.getString(1));
				cpm.setPurchase_type(rs.getString(2));
				cpm.setRequisition_id(rs.getString(3));
				cpm.setDate_time(rs.getString(4));
				cpm.setCustomer_id(rs.getString(5));
				cpm.setCustomer_name(rs.getString(6));
				cpm.setMobile(rs.getString(7));
				cpm.setNeeded_date_time(rs.getString(8));
				cpm.setFrom_account_id(rs.getString(9));
				cpm.setTo_account_id(rs.getString(10));
				cpm.setSalesman_id(rs.getString(11));
				cpm.setTotal_amount(rs.getDouble(12));
				cpm.setOrder_status(rs.getString(13));
				cpm.setDelivery_status(rs.getString(14));
				cpm.setCreated(rs.getString(15));
				cpm.setUpdated(rs.getString(16));
				cpm.setCreated_by(rs.getString(17));
				cpm.setUpdated_by(rs.getString(18));
				
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

		return cpm;
	}
	
	public CustomerPurchaseMain getCustomerPurchaseMainByIdDateTime(String requisition_id, String date_time){
		CustomerPurchaseMain cpm = new CustomerPurchaseMain();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_id, purchase_type, requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM customer_purchase_main where requisition_id=? and date_time=?");
			
			ps.setString(1, requisition_id);
			ps.setString(2, date_time);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				cpm.setPurchase_id(rs.getString(1));
				cpm.setPurchase_type(rs.getString(2));
				cpm.setRequisition_id(rs.getString(3));
				cpm.setDate_time(rs.getString(4));
				cpm.setCustomer_id(rs.getString(5));
				cpm.setCustomer_name(rs.getString(6));
				cpm.setMobile(rs.getString(7));
				cpm.setNeeded_date_time(rs.getString(8));
				cpm.setFrom_account_id(rs.getString(9));
				cpm.setTo_account_id(rs.getString(10));
				cpm.setSalesman_id(rs.getString(11));
				cpm.setTotal_amount(rs.getDouble(12));
				cpm.setOrder_status(rs.getString(13));
				cpm.setDelivery_status(rs.getString(14));
				cpm.setCreated(rs.getString(15));
				cpm.setUpdated(rs.getString(16));
				cpm.setCreated_by(rs.getString(17));
				cpm.setUpdated_by(rs.getString(18));
				
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

		return cpm;
	}
	
	// generated auto increment id during add [S]
	public CustomerPurchaseMain getCustomerPurchaseMainID(){
		CustomerPurchaseMain cpm = new CustomerPurchaseMain();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_id FROM customer_purchase_main");
			
			rs = ps.executeQuery();
			
			int purchase_id = 0;
			
			if(rs.next() == false) {
				purchase_id = 1000000000;
				purchase_id = purchase_id+1;
				cpm.setPurchase_id("CSTP" + String.valueOf(purchase_id));
			} else {
				if(rs.last()) {
					String strCustomerPurchaseMain = rs.getString("purchase_id");
					purchase_id = Integer.parseInt(strCustomerPurchaseMain.replaceAll("[^0-9]", ""));
					purchase_id = purchase_id+1;
					cpm.setPurchase_id("CSTP" + String.valueOf(purchase_id));
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
		
		return cpm;
	}
	// generated auto increment id during add [E]
	
	// selected other respective id during update [S]
	public CustomerPurchaseMain getSelectedOtherID(String purchase_id){
		CustomerPurchaseMain cpm = new CustomerPurchaseMain();
		
		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT purchase_id, requisition_id, date_time, customer_id, salesman_id, order_status, delivery_status, total_amount FROM customer_purchase_main WHERE purchase_id=?");
			
			ps.setString(1, purchase_id);
			
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strCustomerPurchaseMain = rs.getString("purchase_id");
				String strRequisition = rs.getString("requisition_id");
				String strDateTime = rs.getString("date_time");
				String strCustomer = rs.getString("customer_id");
				String strSalesman = rs.getString("salesman_id");
				double dubleTotalAmount = rs.getDouble("total_amount");
				String strOrderStatus = rs.getString("order_status");
				String strDeliveryStatus = rs.getString("delivery_status");
				
				cpm.setPurchase_id(strCustomerPurchaseMain);
				cpm.setRequisition_id(strRequisition);
				cpm.setDate_time(strDateTime);
				cpm.setCustomer_id(strCustomer);
				cpm.setSalesman_id(strSalesman);
				cpm.setTotal_amount(dubleTotalAmount);
				cpm.setOrder_status(strOrderStatus);
				cpm.setDelivery_status(strDeliveryStatus);
				
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
		
		return cpm;
	}
	// selected other respective id during update [E]
	
	// for insert into requisition_multi total_amount from Requisition Product sum total amount [S]
	/*public void sumTotalAmountSP(String purchase_id, String requisition_id, String date_time){
		try{
			ps = con.prepareStatement("UPDATE customer_purchase_main set total_amount=?, updated=? where purchase_id=? and requisition_id=? and date_time=?");
			
			ps.setDouble(1, spdao.sumTotalAmount(purchase_id, requisition_id, date_time).getTotal_amount());
			ps.setString(2, strDate);
			ps.setString(3, purchase_id);
			ps.setString(4, requisition_id);
			ps.setString(5, date_time);
			
			ps.executeUpdate();		
			
		} catch(Exception e){
			e.printStackTrace();
		} finally {
			if(con!=null){
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
	}*/
	// for insert into requisition_multi total_amount from Requisition Product sum total amount [S]
	
	// after approve record copy from requisition to sales [S]
	public void salesMainToCustomerPurchaseMain(String requisition_id, String date_time){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO customer_purchase_main(purchase_id, purchase_type, requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO customer_purchase_main(purchase_id, purchase_type, requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			// generated auto increment id during insertion [S]
			//ps.setString(1, "1000000001");
			CustomerPurchaseMainDAO cpmdao = new CustomerPurchaseMainDAO();
			ps.setString(1, cpmdao.getCustomerPurchaseMainID().getPurchase_id());
			// generated auto increment id during insertion [E]
			ps.setString(2, "Requisition");
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
	// after approve record copy from requisition to sales [S]

}
