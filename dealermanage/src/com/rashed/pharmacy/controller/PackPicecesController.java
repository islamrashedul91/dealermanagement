package com.rashed.pharmacy.controller;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import com.google.zxing.WriterException;

import com.rashed.pharmacy.model.PackPiceces;
import com.rashed.pharmacy.dao.PackPicecesDAO;
import com.rashed.pharmacy.util.*;

public class PackPicecesController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/product/packPicecesAdd.jsp";
	private static String LIST_PACKPIECES = "/jsp/product/packPicecesList.jsp";
	private static String ENQUIRY = "/jsp/product/packPicecesEnquiry.jsp";
	private PackPicecesDAO dao;
	
	String action = "";
	String message = "";
	
       
    public PackPicecesController() {
        super();
        dao = new PackPicecesDAO();
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
			String pack_piceces_id = request.getParameter("pack_piceces_id");
			dao.delete(pack_piceces_id);
			forward=LIST_PACKPIECES;
			request.setAttribute("packPieces", dao.getAllPackPiceces());
			message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String pack_piceces_id = request.getParameter("pack_piceces_id");
			PackPiceces pp = dao.getPackPicecesById(pack_piceces_id);
			request.setAttribute("packPiece", pp);
		} else if(action.equalsIgnoreCase("packPicecesList")){
			forward = LIST_PACKPIECES;
			request.setAttribute("packPieces", dao.getAllPackPiceces());
		}  else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String pack_piceces_id = request.getParameter("pack_piceces_id");
			PackPiceces pp = dao.getPackPicecesById(pack_piceces_id);
			request.setAttribute("packPiece", pp);
		} else {
			forward = INSERT_OR_EDIT;
			// generated auto increment id during add [S]
			request.setAttribute("packPiecesId", dao.getPackPicecesID().getPack_piceces_id());
			// generated auto increment id during add [E]
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		PackPiceces pp = new PackPiceces();
		
		pp.setPack_piceces_id(request.getParameter("pack_piceces_id"));
		pp.setPack_type(request.getParameter("pack_type"));
		pp.setPack_size(request.getParameter("pack_size"));
		pp.setPiceces(Integer.parseInt(request.getParameter("piceces")));
		pp.setCreated(request.getParameter("created"));
		pp.setUpdated(request.getParameter("updated"));
		
		String pack_piceces_id = request.getParameter("pack_piceces_id");
		
		if(action.equalsIgnoreCase("save")){
			dao.save(pp);
		} else if(action.equalsIgnoreCase("edit")){
			pp.setPack_piceces_id(pack_piceces_id);
			dao.update(pp);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_PACKPIECES);
		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		request.setAttribute("packPieces", dao.getAllPackPiceces());
		
		rd.forward(request, response);
	}

}