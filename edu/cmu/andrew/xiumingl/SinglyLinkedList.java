package edu.cmu.andrew.xiumingl;

import edu.colorado.nodes.ObjectNode;

public class SinglyLinkedList {
	private ObjectNode head;
	private ObjectNode tail;
	private ObjectNode iterator;

	public SinglyLinkedList() {
		head = null;
		tail = head;
		iterator = head;
	}

	public void addAtEndNode(Object c) {
		if (head == null) {
			head = new ObjectNode(c, null);
			tail = head;
			iterator = head;
		}else {
			tail.addNodeAfter(c);
			tail = tail.getLink();
		}

	};

	public void addAtFrontNode(Object c) {
		if (head == null) {
			head = new ObjectNode(c, null);
			tail = head;
			iterator = head;
		}else
			head = new ObjectNode(c, head);

	}

	public int countNodes() {
		return ObjectNode.listLength(head);

	}

	public Object getLast() {
		return tail.getData();

	}

	public Object getObjectAt(int i) {
		return ObjectNode.listPosition(head, i).getData();

	}

	public boolean hasNext() {
		if (iterator == null)
			return false;
		else
			return true;

	}

	public Object next() {
		if (iterator == null)
			System.out.println("Already reach the end of the list!");

		Object currentNode = iterator.getData();
		if (iterator == tail)
			iterator = null;
		else
			iterator = iterator.getLink();
		return currentNode;

	}

	public void reset() {
		iterator = head;

	}

	public String toString() {
		return head.toString();

	}

	public static void main(String[] args) {
		// initialize head and SinglyLinkedList
		SinglyLinkedList s = new SinglyLinkedList();

		// addAtEndNode testing
		s.addAtEndNode('D');
		s.addAtEndNode('E');
		s.addAtEndNode('F');
		s.addAtEndNode('G');

		// addAtFrontNode testing
		s.addAtFrontNode('C');
		s.addAtFrontNode('B');
		s.addAtFrontNode('A');

		// countNodes testing
		System.out.println("The number of the data in the singly list is: " + s.countNodes());

		// getLast testing
		System.out.println("The last data in the singly list is: " + s.getLast());

		// getObjectAt testing
		System.out.println("The 4th data in the singly list is: " + s.getObjectAt(3));

		// toString testing
		System.out.println("The data in the singly list are: " + s.toString());

		// iterator testing
		s.reset();
		while (s.hasNext()) {
			System.out.println(s.next());
		}

	}

}
