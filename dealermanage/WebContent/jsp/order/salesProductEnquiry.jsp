<jsp:include page="../../base.jsp"></jsp:include>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet"
	href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/copytest.css" />
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/table.css" />

<script type="text/javascript"
	src="${pageContext.request.contextPath}/js/jquery.min.js"></script>
<script type="text/javascript"
	src="${pageContext.request.contextPath}/js/dataTables/jquery.dataTables.min.js"></script>
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/jquery.dataTables.min.css">

		<div class="mcontent">
			<div class="titlenav">
				<ul>
					<li class="title"><a href="">Sales Product Enquiry</a></li>
					<li class="bread"><a href="">Dashboard > Order
							Management > Sales List > Sales Product List > Sales Product Enquiry</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	
	<form action="" method="post">
		<table id="example" class="display" style="width: 100%" cellspacing="10">			
			<tr>
				<td Class ="FormCellColor" colspan="2">Sales Product ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.sales_product_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Sales ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.sales_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Sales Type</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.sales_type}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Product Requisition ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.requisition_product_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Requisition ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.requisition_id}" /></td>
				<td Class ="FormCellColor" colspan="2">DateTime</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.date_time}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${salesProduct.date_time}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Product ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.product_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Product Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.product_name}" /></td>
				<td Class ="FormCellColor" colspan="2">Pack Type</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.pack_type}" /></td>	
			</tr>
			
			<tr>		
				<td Class ="FormCellColor" colspan="2">Pack Size</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.pack_size}" /></td>
				<td Class ="FormCellColor" colspan="2">Pieces</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.piceces}" /></td>
				<td Class ="FormCellColor" colspan="2"></td>
				<td Class ="FormInputColor" colspan="2"></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Bonus ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.bonus_id}" /></td>			
				<td Class ="FormCellColor" colspan="2">Bonus Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.bonus_name}" /></td>
				<td Class ="FormCellColor" colspan="2">Order Pack</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.order_pack}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Order Quantity</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.order_quantity}" /></td>
				<td Class ="FormCellColor" colspan="2">MRP BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.mrp_price}" /></td>
				<td Class ="FormCellColor" colspan="2">Total MRP BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.total_mrp_price}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Discount Amount BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.discount_amt}" /></td>
				<td Class ="FormCellColor" colspan="2">Total Amount BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.total_amount}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Order Status</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${requisition.order_status}" /></td> --%>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.order_status == 'P' ? 'Pending' : salesProduct.order_status == 'A' ? 'Approved' : salesProduct.order_status == 'C' ? 'Cancel' : salesProduct.order_status == 'S' ? 'Success' : ''}" /></td>
				<td Class ="FormCellColor" colspan="2">Delivery Status</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${requisition.delivery_status}" /></td> --%>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.delivery_status == 'P' ? 'Pending' : salesProduct.delivery_status == 'D' ? 'Delivered' : salesProduct.delivery_status == 'C' ? 'Cancel' : salesProduct.delivery_status == 'S' ? 'Success' : salesProduct.delivery_status == 'R' ? 'Return' : ''}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Created</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.created}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${salesProduct.created}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
				<td Class ="FormCellColor" colspan="2">Updated</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.updated}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${salesProduct.updated}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Created By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.created_by}" /></td>
				<td Class ="FormCellColor" colspan="2">Updated By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesProduct.updated_by}" /></td>
			</tr>
		</table>
		<br>
		
		<table align="center" width="100%">
			
				<tr>
					<td><hr align=left width="100%" color=#003399><br>
						<%-- <a Class ="button" href="${pageContext.request.contextPath}/jsp/order/requisition.jsp">Return</a> --%>
						<%
						String action = (String) session.getAttribute("action");
						if (action.equalsIgnoreCase("enquiryEnquiry")) {
						%>
						<%-- <a Class ="button" href="${pageContext.request.contextPath}/RequisitionMultiController?action=requisitionProductListEnquiry&requisition_id=${requisitionProduct.requisition_id}&date_time=${requisitionProduct.date_time}">Return</a></td> --%>
						<a Class ="button" href="${pageContext.request.contextPath}/SalesMainController?action=salesProductListEnquiry&sales_id=${salesProduct.sales_id}&requisition_id=${salesProduct.requisition_id}&date_time=${salesProduct.date_time}&customer_name=${customer_name}&mobile=${mobile}">Return</a></td>
						<%
						} else {
						%>
						<%-- <a Class ="button" href="${pageContext.request.contextPath}/RequisitionMultiController?action=return&requisition_id=${requisitionProduct.requisition_id}&date_time=${requisitionProduct.date_time}">Return</a></td> --%>
						<a Class ="button" href="${pageContext.request.contextPath}/SalesMainController?action=return&sales_id=${salesProduct.sales_id}&requisition_id=${salesProduct.requisition_id}&date_time=${salesProduct.date_time}&customer_name=${customer_name}&mobile=${mobile}">Return</a></td>
						<%
						}
						%>
					</td>
				</tr>
		</table>
	</form>
	</div>
</div><!-- mcontent -->
	
</div><!-- main -->

	<!-- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -->

</body>
</html>