import { useQuery } from '@tanstack/react-query';
import api from '../api/client';

export const useDevices = () => {
    return useQuery({
        queryKey: ['devices'],
        queryFn: async () => {
            const { data } = await api.get('/devices/');
            return data;
        },
        refetchInterval: 10000, // Refetch every 10 seconds
    });
};

export const useAlerts = () => {
    return useQuery({
        queryKey: ['alerts'],
        queryFn: async () => {
            const { data } = await api.get('/alerts/');
            return data;
        },
        refetchInterval: 5000, // Refetch every 5 seconds
    });
};
