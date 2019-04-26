package com.rashed.pharmacy.controller;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.google.zxing.WriterException;
import com.rashed.pharmacy.model.SalesRate;
import com.rashed.pharmacy.dao.SalesRateDAO;
import com.rashed.pharmacy.util.*;

public class SalesRateController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/product/salesRateAdd.jsp";
	private static String LIST_SALESRATE = "/jsp/product/salesRateList.jsp";
	private static String ENQUIRY = "/jsp/product/salesRateEnquiry.jsp";
	private SalesRateDAO dao;
	
	String action = "";
	String message = "";
	
       
    public SalesRateController() {
        super();
        dao = new SalesRateDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		if(action.equalsIgnoreCase("delete")){
			String sales_rate_id = request.getParameter("sales_rate_id");
			dao.delete(sales_rate_id);
			forward=LIST_SALESRATE;
			request.setAttribute("salesRates", dao.getAllSalesRate());
			message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String sales_rate_id = request.getParameter("sales_rate_id");
			SalesRate sr = dao.getSalesRateById(sales_rate_id);
			request.setAttribute("salesRate", sr);
		} else if(action.equalsIgnoreCase("salesRateList")){
			forward = LIST_SALESRATE;
			request.setAttribute("salesRates", dao.getAllSalesRate());
		}  else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String sales_rate_id = request.getParameter("sales_rate_id");
			SalesRate sr = dao.getSalesRateById(sales_rate_id);
			request.setAttribute("salesRate", sr);
		} else {
			forward = INSERT_OR_EDIT;
			// generated auto increment id during add [S]
			request.setAttribute("salesRateId", dao.getSalesRateID().getSales_rate_id());
			// generated auto increment id during add [E]
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		SalesRate sr = new SalesRate();
		
		sr.setSales_rate_id(request.getParameter("sales_rate_id"));
		sr.setRate_percent(Double.parseDouble(request.getParameter("rate_percent")));
		sr.setDescription(request.getParameter("description"));
		sr.setCreated(request.getParameter("created"));
		sr.setUpdated(request.getParameter("updated"));
		sr.setCreated_by(request.getParameter("created_by"));
		sr.setUpdated_by(request.getParameter("updated_by"));
		
		String sales_rate_id = request.getParameter("sales_rate_id");
		if(action.equalsIgnoreCase("save")){
			dao.save(sr);
		} else if(action.equalsIgnoreCase("edit")){
			sr.setSales_rate_id(sales_rate_id);
			dao.update(sr);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_SALESRATE);
		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		request.setAttribute("salesRates", dao.getAllSalesRate());
		
		rd.forward(request, response);
	}

}
