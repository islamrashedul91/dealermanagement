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
import com.rashed.pharmacy.model.RequisitionMulti;
import com.rashed.pharmacy.util.*;

public class RequisitionMultiDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	private RequisitionProductDAO rpdao;
	
	public RequisitionMultiDAO(){
		//con  = DbUtil.getConnection();
		rpdao = new RequisitionProductDAO();
	}
	
	//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
	Date date = new Date();  
	String strDate = formatter.format(date);
	
	public void save(RequisitionMulti rm){
		
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO requisition_multi(requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO requisition_multi(requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			ps.setString(1, rm.getRequisition_id());
			/*ps.setString(2, strDate);*/
			ps.setString(2, rm.getDate_time());
			ps.setString(3, rm.getCustomer_id());
			ps.setString(4, rm.getCustomer_name());
			ps.setString(5, rm.getMobile());
			ps.setString(6, rm.getNeeded_date_time());
			ps.setString(7, rm.getFrom_account_id());
			ps.setString(8, rm.getTo_account_id());
			ps.setString(9, rm.getSalesman_id());
			ps.setDouble(10, rm.getTotal_amount());
			ps.setString(11, rm.getOrder_status());
			ps.setString(12, rm.getDelivery_status());
			/*ps.setString(13, strDate);*/
			ps.setString(13, rm.getCreated());
			ps.setString(14, rm.getUpdated());
			
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
			//PreparedStatement ps = con.prepareStatement("DELETE FROM requisition_multi WHERE requisition_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM requisition_multi WHERE requisition_id=?");
			
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
	
	public void deleteByIdDateTime(String requisition_id, String date_time){

		try{
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM requisition_multi WHERE requisition_id=? and date_time=?");
			
			ps.setString(1, requisition_id);
			ps.setString(2, date_time);
			
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
	
	public void update(RequisitionMulti rm){

		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE requisition_multi set date_time=?, customer_id=?, customer_name=?, mobile=?, needed_date_time=?, from_account_id=?, to_account_id=?, salesman_id=?, total_amount=?, order_status=?, delivery_status=?, created=?, updated=? where requisition_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE requisition_multi set date_time=?, customer_id=?, customer_name=?, mobile=?, needed_date_time=?, from_account_id=?, to_account_id=?, salesman_id=?, total_amount=?, order_status=?, delivery_status=?, created=?, updated=? where requisition_id=?");
			
			ps.setString(1, rm.getDate_time());
			ps.setString(2, rm.getCustomer_id());
			ps.setString(3, rm.getCustomer_name());
			ps.setString(4, rm.getMobile());
			ps.setString(5, rm.getNeeded_date_time());
			ps.setString(6, rm.getFrom_account_id());
			ps.setString(7, rm.getTo_account_id());
			ps.setString(8, rm.getSalesman_id());
			ps.setDouble(9, rm.getTotal_amount());
			ps.setString(10, rm.getOrder_status());
			ps.setString(11, rm.getDelivery_status());
			ps.setString(12, rm.getCreated());
			/*ps.setString(13, strDate);*/
			ps.setString(13, rm.getUpdated());
			ps.setString(14, rm.getRequisition_id());
			
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
			//PreparedStatement ps = con.prepareStatement("UPDATE requisition_multi set order_status=?, updated=? where requisition_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE requisition_multi set order_status=?, updated=? where requisition_id=?");
			
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
			//PreparedStatement ps = con.prepareStatement("UPDATE requisition_multi set order_status=?, updated=? where requisition_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE requisition_multi set order_status=?, updated=? where requisition_id=?");
			
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
	
	public List<RequisitionMulti> getAllRequisitionMulti(){
		List<RequisitionMulti> list = new ArrayList<RequisitionMulti>();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated FROM requisition_multi ORDER BY created DESC");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated FROM requisition_multi ORDER BY created DESC");
			rs = ps.executeQuery();
			while (rs.next()) {
				RequisitionMulti rm = new RequisitionMulti();				
				
				rm.setRequisition_id(rs.getString(1));
				rm.setDate_time(rs.getString(2));
				rm.setCustomer_id(rs.getString(3));
				rm.setCustomer_name(rs.getString(4));
				rm.setMobile(rs.getString(5));
				rm.setNeeded_date_time(rs.getString(6));
				rm.setFrom_account_id(rs.getString(7));
				rm.setTo_account_id(rs.getString(8));
				rm.setSalesman_id(rs.getString(9));
				rm.setTotal_amount(rs.getDouble(10));
				rm.setOrder_status(rs.getString(11));
				rm.setDelivery_status(rs.getString(12));
				rm.setCreated(rs.getString(13));
				rm.setUpdated(rs.getString(14));
			
				list.add(rm);				
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
	
	public RequisitionMulti getRequisitionMultiById(String requisition_id){
		RequisitionMulti rm = new RequisitionMulti();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated FROM requisition_multi where requisition_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated FROM requisition_multi where requisition_id=?");
			
			ps.setString(1, requisition_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				rm.setRequisition_id(rs.getString(1));
				rm.setDate_time(rs.getString(2));
				rm.setCustomer_id(rs.getString(3));
				rm.setCustomer_name(rs.getString(4));
				rm.setMobile(rs.getString(5));
				rm.setNeeded_date_time(rs.getString(6));
				rm.setFrom_account_id(rs.getString(7));
				rm.setTo_account_id(rs.getString(8));
				rm.setSalesman_id(rs.getString(9));
				rm.setTotal_amount(rs.getDouble(10));
				rm.setOrder_status(rs.getString(11));
				rm.setDelivery_status(rs.getString(12));
				rm.setCreated(rs.getString(13));
				rm.setUpdated(rs.getString(14));
				
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

		return rm;
	}
	
	public RequisitionMulti getRequisitionMultiByIdDateTime(String requisition_id, String date_time){
		RequisitionMulti rm = new RequisitionMulti();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated FROM requisition_multi where requisition_id=? and date_time=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated FROM requisition_multi where requisition_id=? and date_time=?");
			
			ps.setString(1, requisition_id);
			ps.setString(2, date_time);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				rm.setRequisition_id(rs.getString(1));
				rm.setDate_time(rs.getString(2));
				rm.setCustomer_id(rs.getString(3));
				rm.setCustomer_name(rs.getString(4));
				rm.setMobile(rs.getString(5));
				rm.setNeeded_date_time(rs.getString(6));
				rm.setFrom_account_id(rs.getString(7));
				rm.setTo_account_id(rs.getString(8));
				rm.setSalesman_id(rs.getString(9));
				rm.setTotal_amount(rs.getDouble(10));
				rm.setOrder_status(rs.getString(11));
				rm.setDelivery_status(rs.getString(12));
				rm.setCreated(rs.getString(13));
				rm.setUpdated(rs.getString(14));
				
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

		return rm;
	}
	
	// generated auto increment id during add [S]
	public RequisitionMulti getRequisitionMultiID(){
		RequisitionMulti rm = new RequisitionMulti();
		// for get deleted id [S]
		PreparedStatement ps1 = null;
		ResultSet rs1 = null;
		PreparedStatement ps2 = null;
		ResultSet rs2 = null;
		// for get deleted id [E]
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT requisition_id FROM requisition_multi");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT requisition_id FROM requisition_multi");
			
			rs = ps.executeQuery();
			
			int requisition_id = 0;
			// for get deleted id [S]
			int requisition_id1 = 0;
			int requisition_id2 = 0;
			ps1 = con.prepareStatement("SELECT requisition_id FROM sales_main");
			rs1 = ps1.executeQuery();
			ps2 = con.prepareStatement("SELECT requisition_id FROM customer_transaction_main");
			rs2 = ps2.executeQuery();
			
			if (rs.last()) {
				String strRequisition = rs.getString("requisition_id");
				requisition_id = Integer.parseInt(strRequisition.replaceAll("[^0-9]", ""));
			} 
			if (rs1.last()) {
				String strRequisition1 = rs1.getString("requisition_id");
				requisition_id1 = Integer.parseInt(strRequisition1.replaceAll("[^0-9]", ""));
			} 
			if (rs2.last()) {
				String strRequisition2 = rs2.getString("requisition_id");
				requisition_id2 = Integer.parseInt(strRequisition2.replaceAll("[^0-9]", ""));
			}
			
			//if((rs1.next() == false) && (rs2.next() == false) && (rs.next() == false)){
			if((requisition_id == 0) && (requisition_id1 == 0) && (requisition_id2 == 0)){
			// for get deleted id [E]
			
			//if(rs.next() == false) {
				requisition_id = 1000000000;
				requisition_id = requisition_id+1;
				rm.setRequisition_id("REQU" + String.valueOf(requisition_id));
			/*} else {
				if(rs.last()) {
					String strRequisition = rs.getString("requisition_id");
					requisition_id = Integer.parseInt(strRequisition.replaceAll("[^0-9]", ""));
					requisition_id = requisition_id+1;
					rm.setRequisition_id("REQU" + String.valueOf(requisition_id));
				}
			}*/
			// for get deleted id [S]
			} else if ((requisition_id > requisition_id1) && (requisition_id > requisition_id2)) {
				String strRequisition = rs.getString("requisition_id");
				requisition_id = Integer.parseInt(strRequisition.replaceAll("[^0-9]", ""));
				requisition_id = requisition_id+1;
				rm.setRequisition_id("REQU" + String.valueOf(requisition_id));
			} else if (requisition_id1 > requisition_id2) {
				String strRequisition1 = rs1.getString("requisition_id");
				requisition_id = Integer.parseInt(strRequisition1.replaceAll("[^0-9]", ""));
				requisition_id = requisition_id+1;
				rm.setRequisition_id("REQU" + String.valueOf(requisition_id));
			} else if (requisition_id2 > requisition_id1) {
				String strRequisition2 = rs2.getString("requisition_id");
				requisition_id = Integer.parseInt(strRequisition2.replaceAll("[^0-9]", ""));
				requisition_id = requisition_id+1;
				rm.setRequisition_id("REQU" + String.valueOf(requisition_id));
			}
			// for get deleted id [E]
			
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
			if(ps1 != null){
				try {
					ps1.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs1 != null){
				try {
					rs1.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(ps2 != null){
				try {
					ps2.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
			if(rs2 != null){
				try {
					rs2.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
		
		return rm;
	}
	// generated auto increment id during add [E]
	
	// selected other respective id during update [S]
	public RequisitionMulti getSelectedOtherID(String requisition_id){
		RequisitionMulti rm = new RequisitionMulti();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT requisition_id, date_time, customer_id, salesman_id, order_status, delivery_status, total_amount FROM requisition_multi WHERE requisition_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT requisition_id, date_time, customer_id, salesman_id, order_status, delivery_status, total_amount FROM requisition_multi WHERE requisition_id=?");
			
			ps.setString(1, requisition_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strRequisition = rs.getString("requisition_id");
				String strDateTime = rs.getString("date_time");
				String strCustomer = rs.getString("customer_id");
				String strSalesman = rs.getString("salesman_id");
				double dubleTotalAmount = rs.getDouble("total_amount");
				String strOrderStatus = rs.getString("order_status");
				String strDeliveryStatus = rs.getString("delivery_status");
				
				rm.setRequisition_id(strRequisition);
				rm.setDate_time(strDateTime);
				rm.setCustomer_id(strCustomer);
				rm.setSalesman_id(strSalesman);
				rm.setTotal_amount(dubleTotalAmount);
				rm.setOrder_status(strOrderStatus);
				rm.setDelivery_status(strDeliveryStatus);
				
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
		
		return rm;
	}
	// selected other respective id during update [E]
	
	// for insert into requisition_multi total_amount from Requisition Product sum total amount [S]
	public void sumTotalAmountRP(String requisition_id, String date_time){
		
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE requisition_multi set total_amount=?, updated=? where requisition_id=? and date_time=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE requisition_multi set total_amount=?, updated=? where requisition_id=? and date_time=?");
			
			ps.setDouble(1, rpdao.sumTotalAmount(requisition_id, date_time).getTotal_amount());
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
	// for insert into requisition_multi total_amount from Requisition Product sum total amount [S]

}
