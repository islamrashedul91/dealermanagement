package com.rashed.pharmacy.controller;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.google.zxing.WriterException;
import com.rashed.pharmacy.model.SalesmanInfo;
import com.rashed.pharmacy.dao.SalesmanInfoDAO;
import com.rashed.pharmacy.util.*;

public class SalesmanInfoController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/salesman/salesmanInfoAdd.jsp";
	private static String LIST_SALESMANIFO = "/jsp/salesman/salesmanInfoList.jsp";
	private static String ENQUIRY = "/jsp/salesman/salesmanInfoEnquiry.jsp";
	private SalesmanInfoDAO dao;
	
	String action = "";
	String message = "";
	
       
    public SalesmanInfoController() {
        super();
        dao = new SalesmanInfoDAO();
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
			String salesman_id = request.getParameter("salesman_id");
			dao.delete(salesman_id);
			forward=LIST_SALESMANIFO;
			request.setAttribute("salesmanInfos", dao.getAllSalesmanInfo());
			message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String salesman_id = request.getParameter("salesman_id");
			SalesmanInfo smi = dao.getSalesmanInfoById(salesman_id);
			request.setAttribute("salesmanInfo", smi);
		} else if(action.equalsIgnoreCase("salesmanInfoList")){
			forward = LIST_SALESMANIFO;
			request.setAttribute("salesmanInfos", dao.getAllSalesmanInfo());
		}  else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String salesman_id = request.getParameter("salesman_id");
			SalesmanInfo smi = dao.getSalesmanInfoById(salesman_id);
			request.setAttribute("salesmanInfo", smi);
		} else {
			forward = INSERT_OR_EDIT;
			// generated auto increment id during add [S]
			request.setAttribute("salesmanId", dao.getSalesmanInfoID().getSalesman_id());
			// generated auto increment id during add [E]
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		SalesmanInfo smi = new SalesmanInfo();	
		
		smi.setSalesman_id(request.getParameter("salesman_id"));
		smi.setSalesman_name(request.getParameter("salesman_name"));
		smi.setSalesman_desc(request.getParameter("salesman_desc"));
		smi.setSalesman_type(request.getParameter("salesman_type"));
		smi.setSalesman_start_date(request.getParameter("salesman_start_date"));
		smi.setSalesman_position(request.getParameter("salesman_position"));
		smi.setFather_name(request.getParameter("father_name"));
		smi.setMother_name(request.getParameter("mother_name"));
		smi.setNid(request.getParameter("nid"));
		smi.setDob(request.getParameter("dob"));
		smi.setOccupation(request.getParameter("occupation"));
		smi.setHome_address(request.getParameter("home_address"));
		smi.setOffice_address(request.getParameter("office_address"));
		smi.setCountry_id(request.getParameter("country_id"));
		smi.setMobile(request.getParameter("mobile"));
		smi.setEmail(request.getParameter("email"));
		smi.setAccount_id(request.getParameter("account_id"));
		smi.setCreated(request.getParameter("created"));
		smi.setUpdated(request.getParameter("updated"));
		smi.setStatus(request.getParameter("status"));
		
		String salesman_id = request.getParameter("salesman_id");
		String salesman_name = request.getParameter("salesman_name");

		if(action.equalsIgnoreCase("save")){
			dao.save(smi);
		} else if(action.equalsIgnoreCase("edit")){
			smi.setSalesman_id(salesman_id);
			dao.update(smi);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_SALESMANIFO);
		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		request.setAttribute("salesmanInfos", dao.getAllSalesmanInfo());
		
		rd.forward(request, response);
	}

}
