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
					<li class="title"><a href="">Sales Enquiry</a></li>
					<li class="bread"><a href="">Dashboard > Order
							Management > Sales List > Sales Enquiry</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	
	<form action="" method="post">
		<table id="example" class="display" style="width: 100%" cellspacing="10">			
			<tr>
				<td Class ="FormCellColor" colspan="2">Sales ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesMain.sales_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Sales Type</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesMain.sales_type}" /></td>
				<td Class ="FormCellColor" colspan="2"></td>
				<td Class ="FormInputColor" colspan="2"></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Requisition ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesMain.requisition_id}" /></td>
				<td Class ="FormCellColor" colspan="2">DateTime</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${salesMain.date_time}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${salesMain.date_time}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
				<td Class ="FormCellColor" colspan="2">Customer ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesMain.customer_id}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Customer Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesMain.customer_name}" /></td>
				<td Class ="FormCellColor" colspan="2">Mobile</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesMain.mobile}" /></td>
				<td Class ="FormCellColor" colspan="2">Needed Date</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesMain.needed_date_time}" /></td>
			</tr>
			
			<tr>			
				<td Class ="FormCellColor" colspan="2">From Account</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesMain.from_account_id}" /></td>
				<td Class ="FormCellColor" colspan="2">To Account</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesMain.to_account_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Salesman ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesMain.salesman_id}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Total Amount</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesMain.total_amount}" /></td>
				<td Class ="FormCellColor" colspan="2">Order Status</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesMain.order_status == 'P' ? 'Pending' : salesMain.order_status == 'A' ? 'Approved' : salesMain.order_status == 'C' ? 'Cancel' : salesMain.order_status == 'S' ? 'Success' : ''}" /></td>
				<td Class ="FormCellColor" colspan="2">Delivery Status</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesMain.delivery_status == 'P' ? 'Pending' : salesMain.delivery_status == 'D' ? 'Delivered' : salesMain.delivery_status == 'C' ? 'Cancel' : salesMain.delivery_status == 'S' ? 'Success' : salesMain.delivery_status == 'R' ? 'Return' : ''}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Created</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${salesMain.created}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${salesMain.created}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
				<td Class ="FormCellColor" colspan="2">Updated</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${salesMain.updated}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
					<fmt:parseDate pattern="yyyyMMddHHmmss" value="${salesMain.updated}" var="parsedDate" />
					<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Created By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesMain.created_by}" /></td>
				<td Class ="FormCellColor" colspan="2">Updated By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${salesMain.updated_by}" /></td>
			</tr>
		</table>
		<br>
		
		<table align="center" width="100%">
			
				<tr>
					<td><hr align=left width="100%" color=#003399><br>
						<a Class ="button" href="${pageContext.request.contextPath}/SalesMainController?action=salesProductListEnquiry&sales_id=${salesMain.sales_id}&requisition_id=${salesMain.requisition_id}&date_time=${salesMain.date_time}&customer_name=${salesMain.customer_name}&mobile=${salesMain.mobile}">Product Enquiry</a>
						<a Class ="button" href="${pageContext.request.contextPath}/jsp/order/salesMain.jsp">Return</a></td>
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