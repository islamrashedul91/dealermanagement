package com.rashed.pharmacy.controller;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.google.zxing.WriterException;
import com.rashed.pharmacy.model.CustomerInfo;
import com.rashed.pharmacy.dao.CustomerInfoDAO;
import com.rashed.pharmacy.util.*;

public class CustomerInfoController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/customer/customerInfoAdd.jsp";
	private static String LIST_CUSTOMERINFO = "/jsp/customer/customerInfoList.jsp";
	private static String ENQUIRY = "/jsp/customer/customerInfoEnquiry.jsp";
	private CustomerInfoDAO dao;
	
	String action = "";
	String message = "";
	
       
    public CustomerInfoController() {
        super();
        dao = new CustomerInfoDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		if(action.equalsIgnoreCase("delete")){
			//int id=Integer.parseInt(request.getParameter("id"));
			String customer_id = request.getParameter("customer_id");
			dao.delete(customer_id);
			forward=LIST_CUSTOMERINFO;
			request.setAttribute("customerInfos", dao.getAllCustomerInfo());
			message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String customer_id = request.getParameter("customer_id");
			CustomerInfo ci = dao.getCustomerInfoById(customer_id);
			request.setAttribute("customerInfo", ci);
		} else if(action.equalsIgnoreCase("customerInfoList")){
			forward = LIST_CUSTOMERINFO;
			request.setAttribute("customerInfos", dao.getAllCustomerInfo());
		}  else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String customer_id = request.getParameter("customer_id");
			CustomerInfo ci = dao.getCustomerInfoById(customer_id);
			request.setAttribute("customerInfo", ci);
		} else {
			forward = INSERT_OR_EDIT;
			// generated auto increment id during add [S]
			request.setAttribute("customerId", dao.getCustomerInfoID().getCustomer_id());
			// generated auto increment id during add [E]
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		CustomerInfo ci = new CustomerInfo();
		
		ci.setCustomer_id(request.getParameter("customer_id"));
		ci.setCustomer_name(request.getParameter("customer_name"));
		ci.setCustomer_desc(request.getParameter("customer_desc"));
		ci.setCustomer_type(request.getParameter("customer_type"));
		ci.setCustomer_start_date(request.getParameter("customer_start_date"));
		ci.setFather_name(request.getParameter("father_name"));
		ci.setMother_name(request.getParameter("mother_name"));
		ci.setNid(request.getParameter("nid"));
		ci.setDob(request.getParameter("dob"));
		ci.setOccupation(request.getParameter("occupation"));
		ci.setCountry_id(request.getParameter("country_id"));
		ci.setMobile(request.getParameter("mobile"));
		ci.setEmail(request.getParameter("email"));
		ci.setAccount_id(request.getParameter("account_id"));
		ci.setHome_address(request.getParameter("home_address"));
		ci.setOffice_address(request.getParameter("office_address"));
		ci.setProfession(request.getParameter("profession"));
		if(action.equalsIgnoreCase("save")){
			ci.setPassword(request.getParameter("password"));
		}
		ci.setStatus(request.getParameter("status"));
		ci.setCreated(request.getParameter("created"));
		ci.setUpdated(request.getParameter("updated"));
		
		String customer_id = request.getParameter("customer_id");
		String customer_name = request.getParameter("customer_name");
		//String message = "Success!";
		if(action.equalsIgnoreCase("save")){
			dao.save(ci);
		} else if(action.equalsIgnoreCase("edit")){
			ci.setCustomer_id(customer_id);
			dao.update(ci);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_CUSTOMERINFO);
		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		request.setAttribute("customerInfos", dao.getAllCustomerInfo());
		
		rd.forward(request, response);
	}

}
