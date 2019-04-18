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
import com.rashed.pharmacy.model.SalesMain;
import com.rashed.pharmacy.model.RequisitionMulti;
import com.rashed.pharmacy.dao.RequisitionMultiDAO;
import com.rashed.pharmacy.dao.SalesProductDAO;
import com.rashed.pharmacy.util.*;

public class SalesMainDAO {
	
	private Connection con;
	private static Connection conn;
	GetHeader getHeader = new GetHeader();

	private RequisitionMultiDAO rmdao;
	private SalesProductDAO spdao;
	
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public SalesMainDAO(){
		//con  = DbUtil.getConnection();

		rmdao = new RequisitionMultiDAO();
		spdao = new SalesProductDAO();
	}
	
	//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
	Date date = new Date();  
	String strDate = formatter.format(date);
	
	public void save(SalesMain sm){

		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO sales_main(sales_id, sales_type, requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO sales_main(sales_id, sales_type, requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			ps.setString(1, sm.getSales_id());
			ps.setString(2, sm.getSales_type());
			ps.setString(3, sm.getRequisition_id());
			ps.setString(4, sm.getDate_time());
			ps.setString(5, sm.getCustomer_id());
			ps.setString(6, sm.getCustomer_name());
			ps.setString(7, sm.getMobile());
			ps.setString(8, sm.getNeeded_date_time());
			ps.setString(9, sm.getFrom_account_id());
			ps.setString(10, sm.getTo_account_id());
			ps.setString(11, sm.getSalesman_id());
			ps.setDouble(12, sm.getTotal_amount());
			ps.setString(13, sm.getOrder_status());
			ps.setString(14, sm.getDelivery_status());
			ps.setString(15, sm.getCreated());
			ps.setString(16, sm.getUpdated());
			ps.setString(17, sm.getCreated_by());
			ps.setString(18, sm.getUpdated_by());
			
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
	
	public void delete(String sales_id){
		
		try{
			//PreparedStatement ps = con.prepareStatement("DELETE FROM sales_main WHERE sales_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("DELETE FROM sales_main WHERE sales_id=?");
			
			ps.setString(1, sales_id);
			
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
			ps = con.prepareStatement("DELETE FROM sales_main WHERE requisition_id=? and date_time=?");
			
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
	
	public void update(SalesMain sm){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE sales_main set sales_type=?, requisition_id=?, date_time=?, customer_id=?, customer_name=?, mobile=?, needed_date_time=?, from_account_id=?, to_account_id=?, salesman_id=?, total_amount=?, order_status=?, delivery_status=?, created=?, updated=?, created_by=?, updated_by=? where sales_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE sales_main set sales_type=?, requisition_id=?, date_time=?, customer_id=?, customer_name=?, mobile=?, needed_date_time=?, from_account_id=?, to_account_id=?, salesman_id=?, total_amount=?, order_status=?, delivery_status=?, created=?, updated=?, created_by=?, updated_by=? where sales_id=?");
			
			ps.setString(1, sm.getSales_type());
			ps.setString(2, sm.getRequisition_id());
			ps.setString(3, sm.getDate_time());
			ps.setString(4, sm.getCustomer_id());
			ps.setString(5, sm.getCustomer_name());
			ps.setString(6, sm.getMobile());
			ps.setString(7, sm.getNeeded_date_time());
			ps.setString(8, sm.getFrom_account_id());
			ps.setString(9, sm.getTo_account_id());
			ps.setString(10, sm.getSalesman_id());
			ps.setDouble(11, sm.getTotal_amount());
			ps.setString(12, sm.getOrder_status());
			ps.setString(13, sm.getDelivery_status());
			ps.setString(14, sm.getCreated());
			ps.setString(15, sm.getUpdated());
			ps.setString(16, sm.getCreated_by());
			ps.setString(17, sm.getUpdated_by());
			ps.setString(18, sm.getSales_id());
			
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
	
	public void cancel(String sales_id){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE sales_main set order_status=?, updated=? where sales_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE sales_main set order_status=?, updated=? where sales_id=?");
			
			ps.setString(1, "C");
			ps.setString(2, strDate);
			ps.setString(3, sales_id);
			
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
	
	public void approve(String sales_id){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE sales_main set order_status=?, updated=? where sales_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE sales_main set order_status=?, updated=? where sales_id=?");
			
			ps.setString(1, "S");
			ps.setString(2, strDate);
			ps.setString(3, sales_id);
			
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
	
	public void deliveryApprove(String sales_id){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE sales_main set delivery_status=?, updated=? where sales_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE sales_main set delivery_status=?, updated=? where sales_id=?");
			
			ps.setString(1, "D");
			ps.setString(2, strDate);
			ps.setString(3, sales_id);
			
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
	
	public void deliveryReturn(String sales_id){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE sales_main set delivery_status=?, updated=? where sales_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE sales_main set delivery_status=?, updated=? where sales_id=?");
			
			ps.setString(1, "R");
			ps.setString(2, strDate);
			ps.setString(3, sales_id);
			
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
	
	public List<SalesMain> getAllSalesMain(){
		List<SalesMain> list = new ArrayList<SalesMain>();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT sales_id, sales_type, requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM sales_main ORDER BY created DESC");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sales_id, sales_type, requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM sales_main ORDER BY created DESC");
			rs = ps.executeQuery();
			
			while (rs.next()) {
				SalesMain sm = new SalesMain();				
				
				sm.setSales_id(rs.getString(1));
				sm.setSales_type(rs.getString(2));
				sm.setRequisition_id(rs.getString(3));
				sm.setDate_time(rs.getString(4));
				sm.setCustomer_id(rs.getString(5));
				sm.setCustomer_name(rs.getString(6));
				sm.setMobile(rs.getString(7));
				sm.setNeeded_date_time(rs.getString(8));
				sm.setFrom_account_id(rs.getString(9));
				sm.setTo_account_id(rs.getString(10));
				sm.setSalesman_id(rs.getString(11));
				sm.setTotal_amount(rs.getDouble(12));
				sm.setOrder_status(rs.getString(13));
				sm.setDelivery_status(rs.getString(14));
				sm.setCreated(rs.getString(15));
				sm.setUpdated(rs.getString(16));
				sm.setCreated_by(rs.getString(17));
				sm.setUpdated_by(rs.getString(18));
			
				list.add(sm);				
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
	
	public SalesMain getSalesMainById(String sales_id){
		SalesMain sm = new SalesMain();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT sales_id, sales_type, requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM sales_main where sales_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sales_id, sales_type, requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM sales_main where sales_id=?");
			
			ps.setString(1, sales_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				sm.setSales_id(rs.getString(1));
				sm.setSales_type(rs.getString(2));
				sm.setRequisition_id(rs.getString(3));
				sm.setDate_time(rs.getString(4));
				sm.setCustomer_id(rs.getString(5));
				sm.setCustomer_name(rs.getString(6));
				sm.setMobile(rs.getString(7));
				sm.setNeeded_date_time(rs.getString(8));
				sm.setFrom_account_id(rs.getString(9));
				sm.setTo_account_id(rs.getString(10));
				sm.setSalesman_id(rs.getString(11));
				sm.setTotal_amount(rs.getDouble(12));
				sm.setOrder_status(rs.getString(13));
				sm.setDelivery_status(rs.getString(14));
				sm.setCreated(rs.getString(15));
				sm.setUpdated(rs.getString(16));
				sm.setCreated_by(rs.getString(17));
				sm.setUpdated_by(rs.getString(18));
				
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

		return sm;
	}
	
	public SalesMain getSalesMainByIdDateTime(String requisition_id, String date_time){
		SalesMain sm = new SalesMain();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT sales_id, sales_type, requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM sales_main where requisition_id=? and date_time=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sales_id, sales_type, requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated, created_by, updated_by FROM sales_main where requisition_id=? and date_time=?");
			
			ps.setString(1, requisition_id);
			ps.setString(2, date_time);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				sm.setSales_id(rs.getString(1));
				sm.setSales_type(rs.getString(2));
				sm.setRequisition_id(rs.getString(3));
				sm.setDate_time(rs.getString(4));
				sm.setCustomer_id(rs.getString(5));
				sm.setCustomer_name(rs.getString(6));
				sm.setMobile(rs.getString(7));
				sm.setNeeded_date_time(rs.getString(8));
				sm.setFrom_account_id(rs.getString(9));
				sm.setTo_account_id(rs.getString(10));
				sm.setSalesman_id(rs.getString(11));
				sm.setTotal_amount(rs.getDouble(12));
				sm.setOrder_status(rs.getString(13));
				sm.setDelivery_status(rs.getString(14));
				sm.setCreated(rs.getString(15));
				sm.setUpdated(rs.getString(16));
				sm.setCreated_by(rs.getString(17));
				sm.setUpdated_by(rs.getString(18));
				
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

		return sm;
	}
	
	// generated auto increment id during add [S]
	public SalesMain getSalesMainID(){
		SalesMain rm = new SalesMain();
		
		try{
			/*PreparedStatement ps = con.prepareStatement("SELECT sales_id FROM sales_main");
			ResultSet rs = ps.executeQuery();*/
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sales_id FROM sales_main");
			
			rs = ps.executeQuery();
			
			int sales_id = 0;
			
			if(rs.next() == false) {
				sales_id = 1000000000;
				sales_id = sales_id+1;
				rm.setSales_id("SALS" + String.valueOf(sales_id));
			} else {
				if(rs.last()) {
					String strSalesMain = rs.getString("sales_id");
					sales_id = Integer.parseInt(strSalesMain.replaceAll("[^0-9]", ""));
					sales_id = sales_id+1;
					rm.setSales_id("SALS" + String.valueOf(sales_id));
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
		
		return rm;
	}
	// generated auto increment id during add [E]
	
	// selected other respective id during update [S]
	public SalesMain getSelectedOtherID(String sales_id){
		SalesMain sm = new SalesMain();
		
		try{
			//PreparedStatement ps = con.prepareStatement("SELECT sales_id, requisition_id, date_time, customer_id, salesman_id, order_status, delivery_status, total_amount FROM sales_main WHERE sales_id=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("SELECT sales_id, sales_type, requisition_id, date_time, customer_id, salesman_id, order_status, delivery_status, total_amount, from_account_id, to_account_id FROM sales_main WHERE sales_id=?");
			
			ps.setString(1, sales_id);
			
			//ResultSet rs = ps.executeQuery();
			rs = ps.executeQuery();
			
			if(rs.next()){
				
				String strSalesMain = rs.getString("sales_id");
				String strSalesType = rs.getString("sales_type");
				String strRequisition = rs.getString("requisition_id");
				String strDateTime = rs.getString("date_time");
				String strCustomer = rs.getString("customer_id");
				String strSalesman = rs.getString("salesman_id");
				double dubleTotalAmount = rs.getDouble("total_amount");
				String strFromAccount = rs.getString("from_account_id");
				String strToAccount = rs.getString("to_account_id");
				String strOrderStatus = rs.getString("order_status");
				String strDeliveryStatus = rs.getString("delivery_status");
				
				sm.setSales_id(strSalesMain);
				sm.setSales_type(strSalesType);
				sm.setRequisition_id(strRequisition);
				sm.setDate_time(strDateTime);
				sm.setCustomer_id(strCustomer);
				sm.setSalesman_id(strSalesman);
				sm.setTotal_amount(dubleTotalAmount);
				sm.setFrom_account_id(strFromAccount);
				sm.setTo_account_id(strToAccount);
				sm.setOrder_status(strOrderStatus);
				sm.setDelivery_status(strDeliveryStatus);
				
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
		
		return sm;
	}
	// selected other respective id during update [E]
	
	// for insert into requisition_multi total_amount from Requisition Product sum total amount [S]
	public void sumTotalAmountSP(String sales_id, String requisition_id, String date_time){
		try{
			//PreparedStatement ps = con.prepareStatement("UPDATE sales_main set total_amount=?, updated=? where requisition_id=? and date_time=?");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("UPDATE sales_main set total_amount=?, updated=? where sales_id=? and requisition_id=? and date_time=?");
			
			ps.setDouble(1, spdao.sumTotalAmount(sales_id, requisition_id, date_time).getTotal_amount());
			ps.setString(2, strDate);
			ps.setString(3, sales_id);
			ps.setString(4, requisition_id);
			ps.setString(5, date_time);
			
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
	
	// after approve record copy from requisition to sales [S]
	public void requisitionMultiToSalesMain(String requisition_id, String date_time){
		try{
			//PreparedStatement ps = con.prepareStatement("INSERT INTO sales_main(sales_id, sales_type, requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			con  = DbUtil.getConnection();
			ps = con.prepareStatement("INSERT INTO sales_main(sales_id, sales_type, requisition_id, date_time, customer_id, customer_name, mobile, needed_date_time, from_account_id, to_account_id, salesman_id, total_amount, order_status, delivery_status, created, updated, created_by, updated_by) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
			
			// generated auto increment id during insertion [S]
			//ps.setString(1, "1000000001");
			SalesMainDAO smdao = new SalesMainDAO();
			ps.setString(1, smdao.getSalesMainID().getSales_id());
			// generated auto increment id during insertion [E]
			ps.setString(2, "Requisition");
			ps.setString(3, rmdao.getRequisitionMultiByIdDateTime(requisition_id, date_time).getRequisition_id());
			ps.setString(4, rmdao.getRequisitionMultiByIdDateTime(requisition_id, date_time).getDate_time());
			ps.setString(5, rmdao.getRequisitionMultiByIdDateTime(requisition_id, date_time).getCustomer_id());
			ps.setString(6, rmdao.getRequisitionMultiByIdDateTime(requisition_id, date_time).getCustomer_name());
			ps.setString(7, rmdao.getRequisitionMultiByIdDateTime(requisition_id, date_time).getMobile());
			ps.setString(8, rmdao.getRequisitionMultiByIdDateTime(requisition_id, date_time).getNeeded_date_time());
			ps.setString(9, rmdao.getRequisitionMultiByIdDateTime(requisition_id, date_time).getFrom_account_id());
			ps.setString(10, rmdao.getRequisitionMultiByIdDateTime(requisition_id, date_time).getTo_account_id());
			ps.setString(11, rmdao.getRequisitionMultiByIdDateTime(requisition_id, date_time).getSalesman_id());
			ps.setDouble(12, rmdao.getRequisitionMultiByIdDateTime(requisition_id, date_time).getTotal_amount());
			ps.setString(13, rmdao.getRequisitionMultiByIdDateTime(requisition_id, date_time).getOrder_status());
			ps.setString(14, rmdao.getRequisitionMultiByIdDateTime(requisition_id, date_time).getDelivery_status());
			ps.setString(15, rmdao.getRequisitionMultiByIdDateTime(requisition_id, date_time).getCreated());
			ps.setString(16, rmdao.getRequisitionMultiByIdDateTime(requisition_id, date_time).getUpdated());
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
