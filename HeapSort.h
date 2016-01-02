#ifndef HEAP_SORT_H

#define HEAP_SORT_H

#include <stdint.h>


class HeapSortPointers
{
public:
	void heapSort(void **arr, int32_t size)
	{
		/*This will put max element in the index 0*/

		heapify(arr, 0, size-1);

		int32_t high = size - 1;

		while (high > 0)
		{
			/*Swap max element with high index in the array*/
			void *tmp = arr[high];
			arr[high] = arr[0];
			arr[0] = tmp;
			--high;
			/*Ensure heap property on remaining elements*/
			shiftRight(arr, 0, high);
		}

		return;
	}

protected:
	// -1 less, 0 equal, +1 greater.
	virtual int32_t compare(void *p1,void *p2) = 0;

private:
	void shiftRight(void **arr, int32_t low, int32_t high)
	{
		int32_t root = low;
		while ((root*2)+1 <= high)
		{
			int32_t leftChild = (root * 2) + 1;
			int32_t rightChild = leftChild + 1;
			int32_t swapIdx = root;

			/*Check if root is less than left child*/
			if ( compare(arr[swapIdx],arr[leftChild]) < 0 )
			{
				swapIdx = leftChild;
			}
			/*If right child exists check if it is less than current root*/
			if ((rightChild <= high) && ( compare(arr[swapIdx],arr[rightChild]) < 0 ))
			{
				swapIdx = rightChild;
			}

			/*Make the biggest element of root, left and right child the root*/
			if (swapIdx != root)
			{
				void *tmp = arr[root];
				arr[root] = arr[swapIdx];
				arr[swapIdx] = tmp;
				/*Keep shifting right and ensure that swapIdx satisfies
				heap property aka left and right child of it is smaller than
				itself*/
				root = swapIdx;
			}
			else
			{
				break;
			}
		}
		return;
	}

	void heapify(void **arr, int32_t low, int32_t high)
	{
		/*Start with middle element. Middle element is chosen in
		such a way that the last element of array is either its
		left child or right child*/
		int32_t midIdx = (high - low -1)/2;
		while (midIdx >= 0)
		{
			shiftRight(arr, midIdx, high);
			--midIdx;
		}
		return;
	}


};




#endif
