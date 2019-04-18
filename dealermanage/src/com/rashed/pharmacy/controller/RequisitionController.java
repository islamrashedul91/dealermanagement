package com.rashed.pharmacy.controller;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.google.zxing.WriterException;
import com.rashed.pharmacy.model.Requisition;
import com.rashed.pharmacy.dao.RequisitionDAO;
import com.rashed.pharmacy.model.Product;
import com.rashed.pharmacy.dao.ProductDAO;
import com.rashed.pharmacy.model.CustomerInfo;
import com.rashed.pharmacy.dao.CustomerInfoDAO;
import com.rashed.pharmacy.model.Sales;
import com.rashed.pharmacy.dao.SalesDAO;
import com.rashed.pharmacy.model.SalesmanInfo;
import com.rashed.pharmacy.dao.SalesmanInfoDAO;
import com.rashed.pharmacy.util.*;

public class RequisitionController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/order/requisitionAdd.jsp";
	private static String LIST_REQUISITION = "/jsp/order/requisitionList.jsp";
	private static String ENQUIRY = "/jsp/order/requisitionEnquiry.jsp";
	
	private RequisitionDAO rdao;
	private ProductDAO pdao;
	private CustomerInfoDAO cdao;
	private SalesDAO sdao;
	private SalesmanInfoDAO smdao;
	
	String action = "";
	String message = "";
	
       
    public RequisitionController() {
        super();
        rdao = new RequisitionDAO();
        pdao = new ProductDAO();
        cdao = new CustomerInfoDAO();
        sdao = new SalesDAO();
        smdao = new SalesmanInfoDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		if(action.equalsIgnoreCase("delete")){
			String requisition_id = request.getParameter("requisition_id");
			rdao.delete(requisition_id);
			forward=LIST_REQUISITION;
			request.setAttribute("requisitions", rdao.getAllRequisition());
			message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("cancel")){
			String requisition_id = request.getParameter("requisition_id");
			String strOrderStatus = rdao.getSelectedOtherID(requisition_id).getOrder_status();
			if (!strOrderStatus.equals("A")) {
				rdao.cancel(requisition_id);
				message = "Order " + requisition_id + " Cancelled Successfully!!!";
				request.setAttribute("success", message);
			} else {
				message = "Approved Order can not be cancelled !!!";
				request.setAttribute("success", message);
			}
			forward=LIST_REQUISITION;
			request.setAttribute("requisitions", rdao.getAllRequisition());
		} else if(action.equalsIgnoreCase("approve")){
			String requisition_id = request.getParameter("requisition_id");
			String strOrderStatus = rdao.getSelectedOtherID(requisition_id).getOrder_status();
			String strProduct = rdao.getSelectedOtherID(requisition_id).getProduct_id();
			int intOrderQuantity = rdao.getSelectedOtherID(requisition_id).getOrder_quantity();
			if (!strOrderStatus.equals("A") && !strOrderStatus.equals("C")) {
				rdao.approve(requisition_id);
				
				//Sales s = new Sales();
				sdao.requisitionToSales(requisition_id);
				
				pdao.stockUpdate(strProduct, intOrderQuantity);
				
				message = "Order " + requisition_id + " Approved Successfully!!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Cancelled Order can not be Approved !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A")) {
					message = "Already Approved !!!";
					request.setAttribute("success", message);
				}
			}
			forward=LIST_REQUISITION;
			request.setAttribute("requisitions", rdao.getAllRequisition());
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String requisition_id = request.getParameter("requisition_id");
			Requisition r = rdao.getRequisitionById(requisition_id);
			request.setAttribute("requisition", r);
			// for get all the Product_id when update requisition [S]
			request.setAttribute("allProduct", pdao.getAllProduct());
			// for get all the Product_id when update requisition [E]
			// for get all the Customer when update requisition [S]
			request.setAttribute("allCustomer", cdao.getAllCustomerInfo());
			// for get all the Customer when update requisition [E]
			// for get all the Salesman when update requisition [S]
			request.setAttribute("allSalesman", smdao.getAllSalesmanInfo());
			// for get all the Salesman when update requisition [E]
			
			// selected other respective id during update [S]
			request.setAttribute("selectedCustomerId", rdao.getSelectedOtherID(requisition_id).getCustomer_id());
			request.setAttribute("selectedProductId", rdao.getSelectedOtherID(requisition_id).getProduct_id());
			request.setAttribute("selectedBonusId", rdao.getSelectedOtherID(requisition_id).getBonus_id());
			request.setAttribute("selectedSalesmanId", rdao.getSelectedOtherID(requisition_id).getSalesman_id());
			// selected other respective id during update [E]
		} else if(action.equalsIgnoreCase("requisitionList")){
			forward = LIST_REQUISITION;
			request.setAttribute("requisitions", rdao.getAllRequisition());
		} else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String requisition_id = request.getParameter("requisition_id");
			Requisition r = rdao.getRequisitionById(requisition_id);
			request.setAttribute("requisition", r);
		} else {
			forward = INSERT_OR_EDIT;
			// generated auto increment id during add [S]
			request.setAttribute("requisitionId", rdao.getRequisitionID().getRequisition_id());
			// generated auto increment id during add [E]
			
			// for get all the Product_id when add requisition [S]
			request.setAttribute("allProduct", pdao.getAllProduct());
			// for get all the Product_id when add requisition [E]
			// for get all the Customer when add requisition [S]
			request.setAttribute("allCustomer", cdao.getAllCustomerInfo());
			// for get all the Customer when add requisition [E]
			// for get all the Salesman when ad requisition [S]
			request.setAttribute("allSalesman", smdao.getAllSalesmanInfo());
			// for get all the Salesman when add requisition [E]
			
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		Requisition r = new Requisition();
		
		r.setRequisition_id(request.getParameter("requisition_id"));
		r.setCustomer_id(request.getParameter("customer_id"));
		r.setCustomer_name(request.getParameter("customer_name"));
		r.setMobile(request.getParameter("mobile"));
		r.setProduct_id(request.getParameter("product_id"));
		r.setProduct_name(request.getParameter("product_name"));
		r.setPack_type(request.getParameter("pack_type"));
		r.setPack_size(request.getParameter("pack_size"));
		r.setPiceces(Integer.parseInt(request.getParameter("piceces")));
		r.setBonus_id(request.getParameter("bonus_id"));
		r.setBonus_name(request.getParameter("bonus_name"));
		r.setOrder_pack(request.getParameter("order_pack"));
		r.setOrder_quantity(Integer.parseInt(request.getParameter("order_quantity")));
		r.setMrp_price(Double.parseDouble(request.getParameter("mrp_price")));
		r.setTotal_mrp_price(Double.parseDouble(request.getParameter("total_mrp_price")));
		r.setDiscount_amt(Double.parseDouble(request.getParameter("discount_amt")));
		r.setTotal_amount(Double.parseDouble(request.getParameter("total_amount")));
		r.setNeeded_date_time(request.getParameter("needed_date_time"));
		r.setFrom_account_id(request.getParameter("from_account_id"));
		r.setTo_account_id(request.getParameter("to_account_id"));
		r.setSalesman_id(request.getParameter("salesman_id"));
		r.setOrder_status(request.getParameter("order_status"));
		r.setDelivery_status(request.getParameter("delivery_status"));
		r.setCreated(request.getParameter("created"));
		r.setUpdated(request.getParameter("updated"));
	
		String requisition_id = request.getParameter("requisition_id");

		if(action.equalsIgnoreCase("save")){
			rdao.save(r);
		} else if(action.equalsIgnoreCase("edit")){
			r.setRequisition_id(requisition_id);
			rdao.update(r);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_REQUISITION);
		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		request.setAttribute("requisitions", rdao.getAllRequisition());
		
		rd.forward(request, response);
	}

}
